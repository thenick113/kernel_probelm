/*
 * elevator sstf
 */
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>


#define FORWARD 1
#define BACKWARD 0
#define MAX_POSITION ULONG_MAX/2 //ULONG_MAX is the maximal value which can be stored in an unsigned long int variable. /2 since we are working with LOOK.
#define MIN_POSITION 0


struct sstf_data {
    struct list_head queue;
    int direction;
    sector_t current_position;
};




static void sstf_merged_requests(struct request_queue *q, struct request *rq, struct request *next)
{
    list_del_init(&next->queuelist);
}


static int sstf_dispatch(struct request_queue *q, int force)
{   
    struct sstf_data *nd = q->elevator->elevator_data;
    
    struct request *rq;
    
    rq = list_first_entry_or_null(&nd->queue, struct request, queuelist);
    if (rq) {
                list_del_init(&rq->queuelist);
        
                printk("list %llu",blk_rq_pos(rq));
                elv_dispatch_sort(q, rq);
                return 1;
    }

    return 0;
}


//look algorithm
static void sstf_add_request(struct request_queue *q, struct request *rq)
{
   struct sstf_data *nd = q->elevator->elevator_data;
    printk("add %llu --",blk_rq_pos(rq));
    
    if(list_empty(&nd->queue)) //
    {
        //Ensure the spin directio is pointing the correct way
        //such that this element should be dispatched next
        //if no other elements come in
        list_add_tail(&rq->queuelist, &nd->queue);
        printk("only one\n");
    }
    else
    {
        struct list_head *temp;
        int insert_flag = 0;
        sector_t ref_req_sector = q->end_sector; //the head location
        sector_t add_req_sector = blk_rq_pos(rq); // new request's location
        
        unsigned long long af,cf;
        list_for_each(temp,&nd->queue)
        {
            struct request *curr_req = list_entry(temp, struct request, queuelist);
            sector_t curr_req_sector = blk_rq_pos(curr_req); //temp location of the queue
            
            if(add_req_sector >= ref_req_sector) //af is the distance from the disk head to request
                af = add_req_sector - ref_req_sector;
            else
                af = ref_req_sector - add_req_sector;
            
            if(curr_req_sector >= ref_req_sector)  //cf is the distance from the disk head to temp
                cf = curr_req_sector - ref_req_sector;
            else    
                cf = ref_req_sector - curr_req_sector;
            
            if(af <= cf) // if af is closer cf, then added before the temp
            {
                list_add_tail(&rq->queuelist,temp);
                printk("last sector = %llu\n",curr_req_sector);
                insert_flag = 1;
                break;
            }
            ref_req_sector = curr_req_sector;
        }
        if (insert_flag ==0)
        {
            list_add_tail(&rq->queuelist,temp);
            printk("last one\n");
        }
    }
}

static struct request *sstf_former_request(struct request_queue *q, struct request *rq)
{
    struct sstf_data *nd = q->elevator->elevator_data;

    if (rq->queuelist.prev == &nd->queue)
        return NULL;
    return list_entry(rq->queuelist.prev, struct request, queuelist);
}

static struct request *sstf_latter_request(struct request_queue *q, struct request *rq)
{
    struct sstf_data *nd = q->elevator->elevator_data;

    if (rq->queuelist.next == &nd->queue)
        return NULL;
    return list_entry(rq->queuelist.next, struct request, queuelist);
}

static int sstf_init_queue(struct request_queue *q, struct elevator_type *e)
{
    struct sstf_data *nd;
    struct elevator_queue *eq;

    eq = elevator_alloc(q, e);
    if (!eq)
        return -ENOMEM;

    nd = kmalloc_node(sizeof(*nd), GFP_KERNEL, q->node);
    if (!nd) {
        kobject_put(&eq->kobj);
        return -ENOMEM;
    }
    eq->elevator_data = nd;

    INIT_LIST_HEAD(&nd->queue);

    spin_lock_irq(q->queue_lock);
    q->elevator = eq;
    spin_unlock_irq(q->queue_lock);
    return 0;
}

static void sstf_exit_queue(struct elevator_queue *e)
{
    struct sstf_data *nd = e->elevator_data;

    BUG_ON(!list_empty(&nd->queue));
    kfree(nd);
}

static struct elevator_type elevator_sstf = {
    .ops = {
        .elevator_merge_req_fn      = sstf_merged_requests,
        .elevator_dispatch_fn       = sstf_dispatch,
        .elevator_add_req_fn        = sstf_add_request,
        .elevator_former_req_fn     = sstf_former_request,
        .elevator_latter_req_fn     = sstf_latter_request,
        .elevator_init_fn       = sstf_init_queue,
        .elevator_exit_fn       = sstf_exit_queue,
    },
    .elevator_name = "sstf",
    .elevator_owner = THIS_MODULE,
};

static int __init sstf_init(void)
{
    return elv_register(&elevator_sstf);
}

static void __exit sstf_exit(void)
{
    elv_unregister(&elevator_sstf);
}

module_init(sstf_init);
module_exit(sstf_exit);


MODULE_AUTHOR("Group 12-05");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SSTF IO scheduler");