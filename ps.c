struct ps
{
    uint diskseq;
    struct gendisk * disk;
} * pc;

void on_del() 
{
    struct gendisk * d;
    int free = 0;
    lock(disk);
    if (pc->disk == d) {
        lock(io);
        pc->disk = NULL;
        free = 1;
        
    } else {
        if (pc->diskseq < d->diskseq) pc->diskseq = d->diskseq;
    }
    unlock(disk);
    if (free) {
        if (wait_io)
            bd_put();
       
        if (!wait(disk_added)) {
            lock(disk)
                if (!pc->disk) pc->timeout = 1;
            unlock(disk)
        }
        unlock(io);

    }
}

void on_add()
{
    lock(disk)
    int skip = 0;
    struct gendisk * d;
    if (pc->diskseq < d->diskseq) {
        if (pc->disk) {
            lock(io);
                pc->disk = open_bd(new);
                // script
                if (wait_io) {
                    bd_put(old);
                }
            unlock(io);
        } else {
            if (!pc->timedout) {
                pc->disk = open_bd(); // if we timed out, io is no longer held?
                // script
                wake(disk_added); // (is holding io)  // if we timed out?
            }
        }
    } 
    unlock(disk);
}
void read()
{
    // todo: TAKE the disk so it won't be cleared underneath us
    quit = 0;
    lock(io) // what holds up up?
    if (pc->disk) pc->io_in_flight++;
    else quit = 1;
    unlock(io)
    if (quit)
         return KILL;
}

/*

ON REMOVAL:
    wait for io
    free
    WAIT for new disk; we can safely lock <io> because ADD_DISK won't need it; it will find ->disk == NULL;
        BUT HOW will it know if we timed out?





*/