/* cthulhu.c
   Sets up a container using namespaces and cgroups and opens a shell.
   Usage may summon the old gods.

   Based heavily on code by Michael Kerrisk published on LWN.net
   (https://lwn.net/Articles/531245/)
*/

// cgroup headers, for creating cgroups
#include <libcgroup.h>

// stdlib, string and time headers for host name generation
#include <stdlib.h>
#include <string.h>
#include <time.h>

// headers for using namespaces and execution related functions
#include <sys/wait.h>
#include <sched.h>

// just filesystem things
#include <sys/mount.h>
#include <limits.h>
#include <stdio.h>
#include <fcntl.h>

// capabilities stuff, for setting and getting 'em
#include <linux/types.h>
#include <sys/capability.h>

// libnl headers, for manipulating virtual ethernet devices
#include <unistd.h>
#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/route/addr.h>
#include <netlink/route/link/veth.h>
#include <linux/if.h>

// definitions
#define MEMORY_LIMIT 134217728
#define STACK_SIZE 1048576

// random hostname generator
void random_hostname( char *hostname )
{

  const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";
  for( int x = 0; x < 16; x++ )
  {

    int random = rand() % (int) (sizeof alphabet - 1);
    hostname[x] = alphabet[random];

  }

  hostname[16] = '\0';
}

// set up cgroup for container
// this uses libcgroup to create a cgroup
// we also attach the memory controller
// and set a memory limit of MEMORY_LIMIT
struct cgroup *configure_cgroup()
{

  struct cgroup *cgroup;
	int init = cgroup_init();

  if ( init )
  {

    printf( "Container: Error creating cgroup" );
    exit( 1 );

  } else {

    cgroup = cgroup_new_cgroup("cthulhu");
    struct cgroup_controller *memory_cg = cgroup_add_controller( cgroup, "memory" );

    if ( memory_cg )
    {

      cgroup_set_value_uint64( memory_cg, "memory.limit_in_bytes", MEMORY_LIMIT );
      cgroup_set_value_bool( memory_cg, "memory.move_charge_at_immigrate", true );
      cgroup_attach_task( cgroup );
      return( cgroup );

    } else {

      printf( "Container: Error setting memory limit" );
      exit( 1 );

    }
  }
}

// set ip address using netlink
void set_ipaddr( char *interface_name, char *ip_addr )
{

  struct rtnl_addr *addr;
  struct nl_sock   *netlink_socket;
  struct nl_cache  *cache;
  struct nl_addr   *local_address;
  int              interface_index;

  addr  = rtnl_addr_alloc();
  netlink_socket = nl_socket_alloc();

  if ( nl_connect( netlink_socket, NETLINK_ROUTE < 0 ))
  {

    printf( "Error setting IP address %s on %s.\n", ip_addr, interface_name );
    exit( 1 );

  }

  if ( rtnl_link_alloc_cache( netlink_socket, AF_UNSPEC, &cache ) < 0 )
  {

    printf( "Error allocating interface cache whilst setting IP.\n" );
    exit( 1 );
  }

  interface_index = rtnl_link_name2i( cache, interface_name );
  if ( interface_index == 0 )
  {

    printf( "Could not resolve interface name %s\n", interface_name );
    exit( 1 );

  }

  rtnl_addr_set_ifindex( addr, interface_index );

  if ( nl_addr_parse ( ip_addr, AF_INET, &local_address ) < 0 )
  {

    printf( "Error parsing address %s\n", ip_addr );
    exit( 1 );

  }

  char buffer[1024];
  nl_addr2str ( local_address, buffer, 1024 );
  if ( rtnl_addr_set_local( addr, local_address ) < 0 )
  {

    printf( "Error setting local address for %s\n", ip_addr );
    exit( 1 );
  }

  if ( rtnl_addr_add( netlink_socket, addr, 0 ) < 0 )
  {

    printf( "Error setting address %s via netlink\n", ip_addr );
    exit( 1 );
  }

  rtnl_addr_put( addr );
  nl_close( netlink_socket );
  nl_socket_free( netlink_socket );

}

// create a virtual ethernet pair, and assign one side
// of the pair to the given pid
void create_veth( int pid )
{

  struct rtnl_link *link;
  struct rtnl_link *peer_link;
  struct rtnl_link *link_change;
  struct rtnl_link *peer_link_change;

  struct nl_sock   *socket;

  socket = nl_socket_alloc();
  if ( nl_connect( socket, NETLINK_ROUTE ) < 0 )
  {

    printf( "Error connecting to netlink.\n" );
    exit( 1 );

  }

  link = rtnl_link_veth_alloc();
  if( !link )
  {

     printf( "Unable to allocate virtual ethernet device.\n" );
     exit(1);
  }

  rtnl_link_set_name( link, "veth0" );
  peer_link = rtnl_link_veth_get_peer( link );
  rtnl_link_set_name( peer_link, "veth1" );
  rtnl_link_set_ns_pid( peer_link, pid );

  if ( rtnl_link_add( socket, link, NLM_F_CREATE | NLM_F_EXCL ) < 0 )
  {

    printf( "Unable to activate virtual ethernet device.\n" );
    exit(1);

  }

  rtnl_link_put( peer_link );
  rtnl_link_put( link );

  nl_close( socket );
}

// destroy veth pair if it exists
void destroy_veth( )
{

  struct rtnl_link *link;
  struct rtnl_link *peer_link;
  struct nl_sock   *socket;

  socket = nl_socket_alloc();
  if ( nl_connect( socket, NETLINK_ROUTE ) < 0 )
  {

    printf( "Error connecting to netlink.\n" );
    exit( 1 );

  }

  link = rtnl_link_veth_alloc();
  rtnl_link_set_name( link, "veth0" );
  peer_link = rtnl_link_veth_get_peer( link );
  rtnl_link_set_name( peer_link, "veth1" );

  if ( rtnl_link_delete( socket, link ) < 0 )
  {
  
     printf( "Error while cleaning up virtual ethernet devices.\n" );
     exit( 1 );
  }

  rtnl_link_put( link );
  nl_close( socket );
}

// update uid and gid map for user namespace
void update_uid_gid_map( pid_t child_pid )
{
  int uid_fd, gid_fd;

  char *uid_map = NULL, *gid_map = NULL;
  char uid_map_path[PATH_MAX], gid_map_path[PATH_MAX];

  char *map = "0 65535 65535";
  size_t map_len = strnlen( map, 16 );

  snprintf( uid_map_path, PATH_MAX, "/proc/%ld/uid_map", (long) child_pid );
  snprintf( gid_map_path, PATH_MAX, "/proc/%ld/gid_map", (long) child_pid );

  uid_fd = open( uid_map_path, O_RDWR);
  gid_fd = open( gid_map_path, O_RDWR);

  if ( uid_fd == -1 || gid_fd == -1 ) 
  {
    printf( "Error opening UID and GID map for container process.\n" );
    exit( 1 );
  }

  if ( write( uid_fd, map, map_len ) != map_len ) 
  {
    printf( "Error writing UID map for container.\n" );
    exit( 1 );
  }

  if ( write( gid_fd, map, map_len ) != map_len ) 
  {
    printf( "Error writing GID map for container.\n" );
    exit( 1 );
  }

  close(uid_fd);
  close(gid_fd);
}

// the container function
static int start_container(void *arg)
{

  // variables
  char hostname[16];
  cap_t capabilities;

  // sleep for a little bit to get things settled
  sleep( 1 );

  // hello world
  printf( "Container: Hello from pid %d\n", getpid() );

  // Set our cgroup
  printf( "Container: Configuring cgroup..." );
  struct cgroup *memory_cgroup = configure_cgroup();
  printf( "done.\n");

  // we generate and set a random hostname
  printf( "Container: Generating hostname..." );
  random_hostname( hostname );
  sethostname( hostname, 16 ); 
  printf( "done.\n");

  // print host name
  // this is where the first security exploit goes
  char container_hostname[1024];
  container_hostname[1024] = '\0';
  gethostname( container_hostname, 1023 );
  printf( "Container: My hostname is %s\n", container_hostname); 

  // set user
  printf("Container: Attempting to switch to root in the container...");
  setuid(0);
  setgid(0);
  printf("done.\n");
  
  // who are we?
  printf("Container: Effective UID = %ld, effective GID = %ld\n", (long) geteuid(), (long) getegid());
  capabilities = cap_get_proc();
  printf("Container user capabilities: %s\n", cap_to_text(capabilities, NULL));

  // unmount /proc so we can remount it in the new namespace
  // until then we share proc with the host
  printf( "Container: Unmounting /proc filesystem..." );
	if ( mount("none", "/proc", NULL, MS_PRIVATE|MS_REC, NULL) != 0 )
  {
    printf( "Continer: Unmounting /proc in container failed.\n" );
    exit( 1 );
  }
  printf( "done.\n" );

  // set root, this puts us in our "container" filesystem
  printf( "Container: Chroot'ing into the chroot directory..." );
  chroot( "chroot" );
  chdir( "/" );
  printf( "done.\n" );

  // mount proc in new namespace
  printf( "Container: Mounting namespace /proc filesystem..." );
	if ( mount("proc", "/proc", "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL) != 0 )
  {
    printf( "Continer: Remounting /proc in container failed.\n" );
    exit( 1 );
  }
  printf( "done.\n" );

  // set an IP on container side
  printf( "Container: Setting guest IP of 10.0.0.2/24..." );
  set_ipaddr( "veth1", "10.0.0.2/24" ); 
  printf( "done.\n" );

  // let's start a shell!
  printf( "Container: Started container.\n" );
  execl( "/bin/bash", "", (char *) NULL );

}

// this is stupd
void print_banner()
{

  char *banner =  "\n"
                  "   __\n"
                  "\\ (..) /           ▄    █            ▀▀█    █\n"
                  " \\ mm /    ▄▄▄   ▄▄█▄▄  █ ▄▄   ▄   ▄   █    █ ▄▄   ▄   ▄\n"
                  "  |  |    █▀  ▀    █    █▀  █  █   █   █    █▀  █  █   █\n"
                  "  |__|    █        █    █   █  █   █   █    █   █  █   █\n"
                  "  |  |    ▀█▄▄▀    ▀▄▄  █   █  ▀▄▄▀█   ▀▄▄  █   █  ▀▄▄▀█\n"
                  "  |  |\n"
                  "\n"
                  "C  Container\n"
                  "T  Technology for\n"
                  "H  Hardcore\n"
                  "U  Users of\n"
                  "L  Linux that's\n"
                  "H  Hardcore and\n"
                  "U  Useful\n\n";

  printf( "%s", banner );

}

// the main function, entry point for C programs
// commandline parms come in on argv, the count of which are in argc
int main( int argc, char *argv[] )
{

  // for tracking the child
  pid_t child_pid;

  print_banner();

  // we will use the clone syscall to start a child process
  // we use the flags option to set the various namespace options
  // CLONE_NEWPID  - allocate a process namespace, gives container its own PID 1
  // CLONE_NEWNET  - allocate a network namespace for virtual networking, isolated route table, firewall, etc.
  // CLONE_NEWUSER - allocate a user namespace. User and group IDs in container are isolated from host.
  // CLONE_NEWIPC  - Inter-process communication can only be performed with processes in this namespace
  // CLONE_NEWUTS  - Allocate a new UTS structure for this process, meaning its own hostname
  // CLONE_NEWNS   - The original and still the best. The mount namespace isolates the filesystem.
  // SIGCHLD       - This tells our process to return SIGCHLD when done. This helps when using waitpid.
  // - allocate stack for child first, though.
  void *stack = malloc( STACK_SIZE );
  int flags = CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWNS | CLONE_NEWNET | SIGCHLD;

  // start our child process
  child_pid = clone( start_container, (char *)stack + STACK_SIZE, flags, 0 );
  printf( "Created container with host PID of %ld\n", (long) child_pid );

  // set up user map for new user namespace
  printf( "Setting user namespace map..." );
  update_uid_gid_map( child_pid );
  printf( "done.\n" );

  // we set up a virtual ethernet pair, and allocate IP addresses
  // this is used to allow network communication between host and "container"
  printf( "Creating virtual ethernet pair..." );
  create_veth( child_pid );
  printf( "done.\n");

  // set host ip address
  printf( "Setting host IP to 10.0.0.1/24..." );
  set_ipaddr( "veth0", "10.0.0.1/24" );
  printf( "done.\n" );

  // wait for process to exit
  // passing a pointer to the status variable is important.
  // waitpid won't wait so good if you don't. as in not at all.
  int status = 0;
  waitpid( child_pid , &status, 0 );
  printf("Container exited.\n");

  // clean up virtual ethernet devices
  printf( "Cleaning up veth devices..." );
  destroy_veth();
  printf( "done.\n" );

}
