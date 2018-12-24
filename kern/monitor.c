// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/pmap.h>
#include <kern/env.h>
#include <kern/trap.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Display information of the stack", mon_backtrace },
	{ "setcolor", "Set display color of the kernel", mon_setcolor },
	{ "showmappings", "Show mappings between two addresses", mon_showmappings },
	{ "setperm", "Set the permission bits of an addresses", mon_setperm },
	{ "showmem", "Show the contents of a range of given memory", mon_showmem },
	{ "continue", "Continue execution the environment in tf", mon_continue },
	{ "c", "Continue execution the environment in tf", mon_continue },
	{ "stepi", "Execution one instruction of the environment in tf", mon_stepi },
	{ "si", "Execution one instruction of the environment in tf", mon_stepi },
};

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	}
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

int
mon_setcolor(int argc, char **argv, struct Trapframe *tf)
{
	if (argc != 2) {
		cprintf("Usage: setcolor [int]\n");
		return 0;
	}
	COLOR_ = (int)strtol(argv[1], NULL, 0);
	COLOR_ &= ~0x11;
	cprintf("Color set to %x\n", COLOR_);
	return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	// Your code here.
	cprintf("Stack backtrace:\n");
	uint32_t ebp = read_ebp(), eip;
	while (ebp != 0) {
		eip = *((uint32_t *)ebp + 1);
		cprintf("  ebp %08x  eip %08x  args", ebp, eip);
		uint32_t *args = (uint32_t *)ebp + 2;
		for (int i = 0; i < 5; i ++) {
            cprintf(" %08x", args[i]);
        }
		cprintf("\n");
		struct Eipdebuginfo eip_info;
		debuginfo_eip(eip, &eip_info);
		cprintf("         %s:%d: %.*s+%d\n",
				eip_info.eip_file, eip_info.eip_line,
				eip_info.eip_fn_namelen, eip_info.eip_fn_name,
				eip - eip_info.eip_fn_addr);
		ebp = *((uint32_t *)ebp);
	}
	return 0;
}

int
mon_showmappings(int argc, char **argv, struct Trapframe *tf)
{
	extern pte_t *pgdir_walk(pde_t *pgdir, const void *va, int create);
    extern pde_t *kern_pgdir;

	if (argc != 2 && argc != 3) {
		cprintf("Usage: showmappings ADDR1 ADDR2\n       showmappings ADDR\n");
		return 0;
	}

	// Convert string to long and satisfy some assertion
	long begin = strtol(argv[1], NULL, 0);
    long end = (argc == 3 ? strtol(argv[2], NULL, 0) : begin);
	begin = (begin > 0xffffffff ? 0xffffffff : begin);
	end = (end > 0xffffffff ? 0xffffffff : end);
	if (end < begin) {
        long tmp = end;
		end = begin;
		begin = tmp;
    }
    begin = ROUNDDOWN(begin, PGSIZE);
	end = ROUNDUP(end, PGSIZE);
	end = (begin == end ? end + PGSIZE : end);

    for (; begin < end; begin += PGSIZE) {
        cprintf("%08x---%08x: ", begin, begin + PGSIZE);
        pte_t *p = pgdir_walk(kern_pgdir, (void *)begin, 0);
        if (p == NULL) {
            cprintf("No mapping\n");
            continue;
        }
        cprintf("page %08x ", PTE_ADDR(*p));
        cprintf("PTE_P: %x, PTE_W: %x, PTE_U: %x\n", (bool)(*p & PTE_P), (bool)(*p & PTE_W), (bool)(*p & PTE_U));
    }

    return 0;
}

int
mon_setperm(int argc, char **argv, struct Trapframe *tf)
{
	extern pte_t *pgdir_walk(pde_t *pgdir, const void *va, int create);
    extern pde_t *kern_pgdir;

	if (argc != 4) {
		cprintf("Usage: setperm ADDR [clear|set] [P|W|U]\n       setperm ADDR [change] perm\n");
		return 0;
	}

	long addr = strtol(argv[1], NULL, 0);
	pte_t *p = pgdir_walk(kern_pgdir, (void *)addr, 0);
	cprintf("Before: ");
	cprintf("PTE_P: %x, PTE_W: %x, PTE_U: %x\n", (bool)(*p & PTE_P), (bool)(*p & PTE_W), (bool)(*p & PTE_U));

	int perm;
	if (strcmp(argv[2], "change") == 0) {
		cprintf("...Change permission bits...\n");
		perm = (int)strtol(argv[3], NULL, 0);
		*p = *p | perm;
	} else {
		if (argv[3][0] == 'P') perm = PTE_P;
		if (argv[3][0] == 'W') perm = PTE_W;
		if (argv[3][0] == 'U') perm = PTE_U;
		if (strcmp(argv[2], "clear") == 0){
			cprintf("...Clear permission bits...\n");
			*p = *p & (~perm);
		}
		if (strcmp(argv[2], "set") == 0) {
			cprintf("...Set permission bits...\n");
			*p = *p | perm;
		}
	}
	cprintf("After: ");
	cprintf("PTE_P: %x, PTE_W: %x, PTE_U: %x\n", (bool)(*p & PTE_P), (bool)(*p & PTE_W), (bool)(*p & PTE_U));
	return 0;
}

int
mon_showmem(int argc, char **argv, struct Trapframe *tf)
{
	if (argc != 4) {
		cprintf("Usage: showmem [Virtual|Physical] ADDR num\n");
		return 0;
	}
	long addr = strtol(argv[2], NULL, 0);
	long vaddr = argv[1][0] == 'V' ? addr : (long)KADDR(PTE_ADDR((void *)addr));
	int n = (int)strtol(argv[3], NULL, 0);
	for (int i = 0; i < n; i +=4) {
		cprintf("%s Memory at %08x is %08x\n", argv[1], addr + i, *((int *)(vaddr + i)));
	}
	return 0;
}

int
mon_continue(int argc, char **argv, struct Trapframe *tf)
{
	if (argc != 1) {
		cprintf("Usage: c\n       continue\n");
		return 0;
	}
	if (tf == NULL) {
		cprintf("Not in backtrace\n");
		return 0;
	}

	curenv->env_tf = *tf;
	curenv->env_tf.tf_eflags &= ~0x100;
	env_run(curenv);
	return 0;
}

int
mon_stepi(int argc, char **argv, struct Trapframe *tf)
{
	if (argc != 1) {
		cprintf("Usage: si\n       stepi\n");
		return 0;
	}
	if (tf == NULL) {
		cprintf("Not in backtrace\n");
		return 0;
	}

	curenv->env_tf = *tf;
	curenv->env_tf.tf_eflags |= 0x100;
	env_run(curenv);
	return 0;
}


/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");

	if (tf != NULL)
		print_trapframe(tf);

	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}
