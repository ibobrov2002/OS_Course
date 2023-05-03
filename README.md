# OS_Course

This branch contains vastly improoved kernel memory subsystem with following new features:

    * 2M/1G pages
    
    * Lazy copying/lazy memory allocation
    
        * Used for speeding up ASAN memory allocation
        
        * Kernel memory is also lazily allocated
        
    * NX flag
    
    * Buddy physical memory allocator
    
    * O((log N)^2) region manipulation
    
    * More convinient syscall API
    
    * IPC with memory regions of size larger than 4K
    
        * Not used at the moment but would be useful for file server optimization
          
    * Reduced memory consumption by a lot
    
    * All supported sanitizers can work simultaniously with any amount of memory (as long as bootloader can allocate enough memory for the kernel)

The code is mostly located in kern/pmap.c

A set of trees is used for holding metadata (nodes are of type struct Page):

    * A tree describing physical memory
    
    * One tree for every address space (for every environment and kernel)

TODO

    * Replace user_mem_assert with exception-based code
    
        * copyin/copyout functions
        
    * Refactor address space and move all kernel-only memory
      regions to cannonical upper part of adress space
      (this requeres copyin/copyout functions because
       ASAN should never touch userspace memory)
