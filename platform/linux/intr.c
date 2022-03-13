#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>

#include "platform.h"

#include "util.h"
#include "net.h"

// irq_entry manages IRQ(Interrupt Request Query)s
struct irq_entry
{
    struct irq_entry *next; // a pointer to next entry
    unsigned int irq; // IRQ number which identifies each entry
    int (*handler)(unsigned int irq, void *dev); // IRQ handler which is invoked on each interruption
    int flags; // if specified INTR_IRQ_SHARED, the entry can be shared
    char name[16]; // name for debugging
    void *dev; // a device occurring an interruption
};

/* NOTE: if you want to add/delete the entries after intr_run(), you need to protect these lists with a mutex. */
static struct irq_entry *irqs;

// a set of signals
static sigset_t sigmask;

// a thread ID for an interruption
static pthread_t tid;

// barrier is for synchronizing each thread
static pthread_barrier_t barrier;

// intr_request_irq 
int intr_request_irq(unsigned int irq, int (*handler)(unsigned int irq, void *dev), int flags, const char *name, void *dev)
{
    struct irq_entry *entry;

    debugf("irq=%u, flags=%d, name=%s", irq, flags, name);
    for (entry = irqs; entry; entry = entry->next)
    {
        if (entry->irq == irq)
        {
            if (entry->flags ^ INTR_IRQ_SHARED || flags ^ INTR_IRQ_SHARED)
            {
                errorf("conflicts with already registered IRQs");
                return -1;
            }
        }
    }
    entry = memory_alloc(sizeof(*entry));
    if (!entry)
    {
        errorf("memory_alloc() failure");
        return -1;
    }
    entry->irq = irq;
    entry->handler = handler;
    entry->flags = flags;
    strncpy(entry->name, name, sizeof(entry->name) - 1);
    entry->dev = dev;
    entry->next = irqs;
    irqs = entry;
    sigaddset(&sigmask, irq);
    debugf("registered: irq=%u, name=%s", irq, name);
    return 0;
}

// intr_raise_irq sends a signal to a thread for managing an interruption
int intr_raise_irq(unsigned int irq)
{
    return pthread_kill(tid, (int)irq);
}

static int intr_timer_setup(struct itimerspec *interval)
{
    timer_t id;

    if (timer_create(CLOCK_REALTIME, NULL, &id) == -1)
    {
        errorf("timer_create: %s", strerror(errno));
        return -1;
    }
    if (timer_settime(id, 0, interval, NULL) == -1)
    {
        errorf("timer_settime: %s", strerror(errno));
        return -1;
    }

    return 0;
}

// intr_thread runs thread for waiting signals corresponding orders as an entrypoint 
static void *intr_thread(void *arg)
{
    const struct timespec ts = {0, 1000000}; // 1ms
    struct itimerspec interval = {ts, ts};

    int terminate = 0, sig, err;
    struct irq_entry *entry;

    debugf("start...");
    pthread_barrier_wait(&barrier);
    if (intr_timer_setup(&interval) == -1)
    {
        errorf("intr_timer_setup() failure");
        return NULL;
    }
    while (!terminate)
    {
        err = sigwait(&sigmask, &sig);
        if (err)
        {
            errorf("sigwait() %s", strerror(err));
            break;
        }
        switch (sig)
        {
        case SIGHUP: // for notifying a signal to an interrupting thread
            terminate = 1;
            break;
        case SIGALRM: // for periodic execution
            net_timer_handler();
            break;
        case SIGUSR1: // intentionally interruption for popping data
            net_softirq_handler();
            break;
        case SIGUSR2: // for capturing evnet signal
            net_event_handler();
            break;
        default:
            for (entry = irqs; entry; entry = entry->next)
            {
                if (entry->irq == (unsigned int)sig)
                {
                    debugf("irq=%d, name=%s", entry->irq, entry->name);
                    entry->handler(entry->irq, entry->dev);
                }
            }
            break;
        }
    }
    debugf("terminated");
    return NULL;
}

// intr_run runs a thread for manaing one interruption
int intr_run(void)
{
    int err;

    err = pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
    if (err)
    {
        errorf("pthread_sigmask() %s", strerror(err));
        return -1;
    }
    err = pthread_create(&tid, NULL, intr_thread, NULL);
    if (err)
    {
        errorf("pthread_create() %s", strerror(err));
        return -1;
    }
    pthread_barrier_wait(&barrier);
    return 0;
}

// intr_shutdown finishs a thread for interruption
void intr_shutdown(void)
{
    if (pthread_equal(tid, pthread_self()) != 0)
    {
        /* Thread not created. */
        return;
    }
    pthread_kill(tid, SIGHUP);
    pthread_join(tid, NULL);
}

// intr_init initializes interruption
int intr_init(void)
{
    tid = pthread_self();
    pthread_barrier_init(&barrier, NULL, 2);
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGHUP);
    sigaddset(&sigmask, SIGALRM);
    sigaddset(&sigmask, SIGUSR1);
    sigaddset(&sigmask, SIGUSR2);
    return 0;
}