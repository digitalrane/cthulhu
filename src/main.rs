// cthulhu.rs
//    Sets up a container using namespaces and cgroups and opens a shell.
//    Usage may summon the old gods.
//
//    Based heavily on code by Michael Kerrisk published on LWN.net
//    (https://lwn.net/Articles/531245/)
//
//    Originally in C, ported to Rust because Rust is a m a z i n g
//    and also because I enjoyed it.

// cgroup-rs is used as an interface to Linux cgroups.
use cgroups_rs::*;
use cgroups_rs::cgroup_builder::*;

// these are standard linux syscalls we use in this program
// they will be detailed as we use them in more specific comments
// generally, however, they are used to set and validate specific
// things like hostnames and user IDs inside the container
use nix::unistd::{geteuid, getegid, setgid, setuid, gethostname, sethostname, getpid, chroot, chdir, Pid, Uid, Gid};
use nix::mount::{mount, umount, MsFlags};
use nix::sched::CloneFlags;
use nix::sys::wait::WaitPidFlag;

// use the rust std::process wrapper for calling our container entrypoint
use std::process::{Command, Stdio};

// the rand crate is used to generate per-container hostnames
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;

// the IPaddr crate is used to handle our local IPs
use std::net::{IpAddr, Ipv4Addr};
use std::thread::sleep;
use std::time::Duration;

// headers for using namespaces and execution related functions
// #include <sys/wait.h>
// #include <sched.h>

// just filesystem things, for writing our files into /proc to set UID and GID maps
use std::fs;

// capabilities stuff, for setting and getting 'em
use caps::{CapSet, Capability, CapsHashSet};

// netlink (rtnetlink) crate, for manipulating virtual ethernet devices
// and the addresses and routes assigned to them, for container networking
// there are other crates which are much more low level, but this one
// provides a nice clean abstraction which demonstrates the actual process
// of talking to netlink much more cleanly
use rtnetlink::{new_connection, Handle};
// we use this so we can stream the responses from netlink, it's not super
// important to understanding how containers work, it's mostly just an
// implementaiton detail for how this program is written, as it is
// an async program
use futures::stream::TryStreamExt;

// a helper library used by rtnetlink to convert IPs to netlink messages
// we import it so we can provide IpNetwork instances to rtnetlink
use ipnetwork::IpNetwork;

// logging library (fern) to help us with log levels and generally
// cleaning up log messages
use fern::colors::{Color, ColoredLevelConfig};
use log::{debug,info,warn};

// set up logger so we can have nice, colourful logs, and helpfule
// logging functions like info!
async fn configure_logging() {
    fern::Dispatch::new()
	.format(|out, message, record| {
	    let colors = ColoredLevelConfig::new()
		.info(Color::Green)
		.warn(Color::Yellow)
		.error(Color::Red)
		.debug(Color::White);

            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
		colors.color(record.level()),
                record.target(),
                message
            ))
	})
	.level(log::LevelFilter::Info)
	.chain(std::io::stdout())
	.apply().unwrap();
}

// random hostname generator
fn random_hostname() -> String {
    thread_rng()
	.sample_iter(&Alphanumeric)
	.take(16)
	.map(char::from)
	.collect()
}

// set up cgroup for the container
// this uses libcgroup to create a cgroup, via CgroupBuilder as an abstraction
// we also attach the memory controller to the cgroup, with a limit of 1GB memory
// we then attach 85 CPU shared to the group via the CPU controller.
// shares are representative, and 1024 shares represents 100% of CPU shares.
// if you were in the root cgroup, this would represent shares of system CPU,
// if you are underneath another cgroup in the hierarchy, then you would get a
// portion of your parent cgroup's shares.
fn configure_cgroup() -> Cgroup {

    // automatically select the current hierarchy to slot into
    let h: Box<dyn Hierarchy> = cgroups_rs::hierarchies::auto();

    // build ourselves a little cgroup
    CgroupBuilder::new("cthulhu")
	// get a reference to the memory cgroup subsystem
	.memory()
	// here we set limits on the memory cgroup subsystem
        .kernel_memory_limit(1024 * 1024)
        .memory_hard_limit(1024 * 1024)
	// we're done with the memory cgroup subsystem
        .done()
	// get a reference to the cpu cgroup subsystem
        .cpu()
	// set a share limit on cpu usage
        .shares(85)
	// we're done with this group subsystem now, you get the idea
        .done()
        // if you like, you could add more cgroup subsystems to our cgroup
	// things like block IO, networking, and hugepages can also be controlled
        .build(h)
}

// set ip address using netlink. we use the rtnetlink crate
// to help abstract working with the netlink interface.
// the netlink interface is a bidirectional communication channel
// with the Linux kernel which allows us to control and query
// various aspects of the kernel, predominantly regarding the
// networking stack.
async fn set_ipaddr(interface_name: &str, ip_addr: IpNetwork, handle: Handle) {

    let mut links = handle
        .link()
        .get()
        .match_name(interface_name.to_string())
        .execute();

    let link = match links.try_next().await {
	Ok(Some(link)) => link,
	Ok(None) => panic!("could not find link matching interface {}", interface_name),
	Err(e) => panic!("could not find link matching interface {}: {:?}", interface_name, e)
    };
    
    match handle
        .address()
        .add(link.header.index, ip_addr.ip(), ip_addr.prefix())
        .execute().await {
	    Ok(_) => info!("set IP address for {} to {}", interface_name, ip_addr.to_string()),
	    Err(e) => panic!("failed to create veth pair: {:?}", e)
	}
}

// create a virtual ethernet pair, and assign one side of the pair to the given pid
// where the pid represents the PID 1 of the container.
// this effectively moves one side of the veth into the network namespace of the container
async fn create_veth(handle: Handle)
{
    match handle
        .link()
        .add()
        .veth("veth0".into(), "veth1".into())
        .execute().await {
	    Ok(_) => info!("created veth pair"),
	    Err(e) => panic!("failed to create veth pair: {:?}", e)
	}
}

// move the container veth into the container namespace
async fn send_container_veth(pid: Pid, handle: Handle) {
    
    // move the container-side veth into the namespace assosciated with the container PID
    let u32_pid: u32 = match pid.as_raw().try_into() {
	Ok(p) => p,
	Err(e) => panic!("Could not convert PID into u32: {:?}", e)
    };

    let mut links = handle.link().get().match_name("veth1".to_string()).execute();
    let link = match links.try_next().await {
	Ok(Some(link)) => link,
	Ok(None) => panic!("could not find link matching container interface"),
	Err(e) => panic!("could not find link matching container interface: {:?}", e)
    };

    match handle
        .link()
        .set(link.header.index)
        .setns_by_pid(u32_pid)
        .execute().await {
	    Ok(_) => info!("moved veth1 into the container namespace"),
	    Err(e) => panic!("failed to move container veth interface into container: {:?}", e)
	}
}

// destroy veth pair if it exists
async fn destroy_veth(handle: Handle)
{

    let mut links = handle.link().get().match_name("veth0".to_string()).execute();
    let link = match links.try_next().await {
	Ok(Some(link)) => link,
	Ok(None) => panic!("could not find link matching container interface during deletion"),
	Err(e) => panic!("could not find link matching container interface during deletion: {:?}", e)
    };
    
    match handle
        .link()
        .del(link.header.index)
        .execute().await {
	    Ok(_) => info!("deleted veth pair"),
	    Err(e) => panic!("failed to delete veth pair: {:?}", e)
	}
}

// update uid and gid map for user namespace
fn update_uid_gid_map( pid: Pid ) {

    const MAP: &str = "0 65535 65535";

    let uid_map_path: String = format!("/proc/{}/uid_map", pid);
    let gid_map_path: String = format!("/proc/{}/gid_map", pid);

    match fs::write(uid_map_path, MAP) {
	Ok(_) => debug!("Updated UID map for process {}", pid),
	Err(e) => panic!("Failed to update UID map for process {}: {:?}", pid, e)
    };
    match fs::write(gid_map_path, MAP) {
	Ok(_) => debug!("Updated GID map for process {}", pid),
	Err(e) => panic!("Failed to update GID map for process {}: {:?}", pid, e)
    };
}

// the container function
fn start_container() -> isize
{

    // sleep for a little bit to get things settled
    sleep(Duration::from_millis(1000));

    // hello world
    info!("Container: Hello from pid {}!", getpid());

    // Set our cgroup
    info!("Container: Configuring cgroup" );
    configure_cgroup();

    // we generate and set a random hostname
    info!("Container: Generating hostname");
    let hostname: String = random_hostname();
    match sethostname(hostname.clone()) {
	Ok(_) => debug!("Container: Set hostname {}", hostname),
	Err(e) => panic!("Container: Failed to set hostname to {}: {:?}", hostname, e)
    }

    // print host name
    // in the C version I had a funny comment about this being where the security vulnerability was
    // I guess in rust, I don't need to worry about quickly hacked together buffer math? right?
    let mut hostname_buf = [0u8; 64];
    let container_hostname_cstr = match gethostname(&mut hostname_buf) {
	Ok(hn) => hn,
	Err(e) => panic!("Container: Failed to get hostname for verification: {:?}", e)
    };
    let container_hostname = match container_hostname_cstr.to_str() {
	Ok(hn) => hn,
	Err(e) => panic!("Container: returned hostname was not able to be converted from CStr: {:?}", e)
    };
    
    info!("Container: My hostname is {}", container_hostname);

    // unmount /proc so we can remount it in the new namespace
    // until then we share proc with the host
    // this mount operation only operates within the mount namespace assosciated
    // with this child container PID this code is running in, so does not impact
    // the actual mounted "host" /proc filesystem! wild.
    info!( "Container: Unmounting host /proc filesystem" );
    match umount("/proc") {
	Ok(_) => debug!("Container: Unmounted /proc"),
	Err(e) => warn!("Container: Could not unmount host /proc from container: {:?}", e)
    }

    // set root, this puts us in our "container" filesystem
    info!( "Container: Chroot'ing into the chroot directory" );
    match chroot("chroot") {
	Ok(_) => debug!("Container: chroot'd into the container filesystem"),
	Err(e) => panic!("Container: failed to chroot into container filesystem: {:?}", e)
    }
    info!("Container: Changing directory to / in the chroot");
    match chdir("/") {
	Ok(_) => debug!("Container: changed directory to /"),
	Err(e) => panic!("Container: failed to change directory to /: {:?}", e)
    }

    // mount proc in new namespace
    // the proc you mount inside the namespace is important because it is
    // specially scoped to the process running inside the proc namespace we
    // were cloned into. i.e., we can't interact with host processes via this /proc
    info!( "Container: Mounting namespace scoped /proc filesystem..." );
    let mount_flags = MsFlags::MS_NOSUID|MsFlags::MS_NOEXEC|MsFlags::MS_NODEV;
    match mount(Some("proc"), "/proc", Some("proc"), mount_flags, Some("")) {
	Ok(_) => debug!("Container: mounted container /proc filesystem"),
	Err(e) => panic!("Continer: Remounting /proc in container failed: {:?}", e )
    }
    
    // set user
    info!("Container: Switching to root user in the container");
    match setuid(Uid::from_raw(0)) {
	Ok(_) => debug!("Container: switched to UID 0"),
	Err(e) => panic!("Container: failed to switch to UID 0: {:?}", e)
    }
    match setgid(Gid::from_raw(0)) {
	Ok(_) => debug!("Container: switched to GID 0"),
	Err(e) => panic!("Container: failed to switch to GID 0: {:?}", e)
    }
  
    // who are we?
    let container_uid = geteuid();
    let container_gid = getegid();
    info!("Container: Effective UID = {}, effective GID = {}", container_uid, container_gid);

    // and what do we do?
    let capabilities = match caps::read(None, CapSet::Effective) {
	Ok(caps) => caps,
	Err(e) => panic!("Container: failed to get effective capabilities: {:?}", e)
    };
    info!("Container: initial user capabilities: {:?}", capabilities);
    
    // Clear all effective caps.
    match caps::clear(None, CapSet::Effective) {
	Ok(_) => info!("Container: cleared all capabilities."),
	Err(e) => panic!("Container: failed to clear capabilities: {:?}", e)
    };
    let capabilities = match caps::read(None, CapSet::Effective) {
	Ok(caps) => caps,
	Err(e) => panic!("Container: failed to get effective capabilities: {:?}", e)
    };
    info!("Container: user capabilities after clear: {:?}", capabilities);

    // Let's limit the capabilities a bit
    // you should listen to Wade and not give your containers CAP_*_ADMIN
    // CAP_NET_RAW is also considered problematic for certain container environments,
    // given the ability to potentially interact with traffic outside of the network namespace
    //
    // So, let's set a sensible list of minimal capabilities for our unprivileged containers
    let mut new_caps = CapsHashSet::new();
    new_caps.insert(Capability::CAP_CHOWN);
    new_caps.insert(Capability::CAP_FOWNER);
    new_caps.insert(Capability::CAP_FSETID);
    new_caps.insert(Capability::CAP_KILL);
    new_caps.insert(Capability::CAP_SETFCAP);
    new_caps.insert(Capability::CAP_SETGID);
    new_caps.insert(Capability::CAP_SETPCAP);
    new_caps.insert(Capability::CAP_SETUID);

    match caps::set(None, CapSet::Effective, &new_caps) {
	Ok(_) =>  info!("Container: set new capabilities"),
	Err(e) => panic!("Container: failed to set new capabilities: {:?}", e)
    };
       
    let capabilities = match caps::read(None, CapSet::Effective) {
	Ok(caps) => caps,
	Err(e) => panic!("Container: failed to get effective capabilities: {:?}", e)
    };
    info!("Container: user capabilities after update: {:?}", capabilities);
    
    // let's start a shell!
    info!("Container: Started container. Now starting shell.");
    let mut child = match Command::new("/bin/bash")
        .arg("-i")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())	
        .spawn() {
	    Ok(child) => child,
	    Err(e) => panic!("Failed to run container shell: {:?}", e)
	};
    match child.wait() {
	Ok(_) => debug!("shell process wait complete"),
	Err(e) => panic!("error returned from subprocess wait: {:?}", e)
    }
    0
}

// this is stupid but I like it
async fn print_banner()
{

  let banner = "
                __
             \\ (..) /           ▄    █            ▀▀█    █
              \\ mm /    ▄▄▄   ▄▄█▄▄  █ ▄▄   ▄   ▄   █    █ ▄▄   ▄   ▄
               |  |    █▀  ▀    █    █▀  █  █   █   █    █▀  █  █   █
               |__|    █        █    █   █  █   █   █    █   █  █   █
               |  |    ▀█▄▄▀    ▀▄▄  █   █  ▀▄▄▀█   ▀▄▄  █   █  ▀▄▄▀█
               |  |
            
             C  Container
             T  Technology for
             H  Hardcore
             U  Users of
             L  Linux that's
             H  Hardcore and
             U  Useful\n";

  info!("{}", banner);
}

// this is a little helper to make our async program (tokio) happy
// whilst waiting for the waitpid syscall, so we actually block further
// execution. we await on this in the main program.
// the waitpid syscall is used to wait on the container PID1 using it's normal PID
async fn wait_for_container(pid: Pid) {
    match tokio::task::spawn_blocking(move || {
	// we explicitly call waitpid with the __CLONE wait flag to make sure
	// our cloned process is waited for
	info!("Waiting for PID {}", pid);
	match nix::sys::wait::waitpid(pid, Some(WaitPidFlag::__WCLONE)) {
	    Ok(_) => debug!("waitpid on container finished"),
	    Err(e) => panic!("error whilst waiting on container PID: {:?}", e)
	}
    }).await {
	Ok(_) => debug!("Blocking async wait on waitpid complete."),
	Err(e) => panic!("Failed to async wait on waitpid tokio task: {:?}", e)
    }
    info!("Container exited.");
}

// the main function, entry point for *nix programs
// commandline parms come in on argv, the count of which are in argc in C, passed as parameters to main by libc
// in Rust, this is abstracted by env::args
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    // configure the logging helper, for pretty logs
    configure_logging().await;

    // print our amazing artworks via logging
    print_banner().await;

    // we will use the clone syscall to start a child process
    // we use the flags option to set the various namespace options for our new cloned process
    // this process allows our new PID to start inside of a new namespace, making it a "container".
    // this is exactly how things like chroot work, and the basis of more complicated container engines
    // such as docker.
    //
    // these flags are OR'd together to make the final flag parameter
    //
    // CLONE_NEWPID  - allocate a process namespace, gives container its own PID 1 (which will be the cloned process)
    // CLONE_NEWNET  - allocate a network namespace for virtual networking, isolated route table, firewall, etc.
    // CLONE_NEWUSER - allocate a user namespace. User and group IDs in container are isolated from host.
    // CLONE_NEWIPC  - Inter-process communication can only be performed with processes in this namespace
    // CLONE_NEWUTS  - Allocate a new UTS structure for this process, meaning its own hostname
    // CLONE_NEWNS   - The original and still the best. The mount namespace isolates the filesystem.
    // SIGCHLD       - This tells our process to return SIGCHLD when done. This helps when using waitpid.
    let flags: CloneFlags = CloneFlags::CLONE_NEWPID|CloneFlags::CLONE_NEWUSER|CloneFlags::CLONE_NEWIPC|CloneFlags::CLONE_NEWUTS|CloneFlags::CLONE_NEWNS|CloneFlags::CLONE_NEWNET;

    // allocate some space on the stack for our new cloned process
    const STACK_SIZE: usize = 1024 * 1024;
    let mut stack: [u8; STACK_SIZE] = [0; STACK_SIZE];

    // create a connection to netlink
    // we spawn the connection as a tokio task so it can be reused
    // by create_veth, destroy_veth and set_ipaddr without blocking
    // this main function. The tokio task will maintain the netlink
    // connection in the background.
    let (connection, handle, _) = match new_connection() {
	Ok(result) => {
	    debug!("got netlink connection for creating veth pair");
	    result
	},
	Err(e) => panic!("could not connect to netlink to create veth pair: {:?}", e)
    };
    tokio::spawn(connection);
    
    // start our child process using the clone syscall
    // this is basically how all containers work!
    info!("Host process is PID {}", nix::unistd::getpid());    
    info!("Attempting to clone ourselves to create a new container parent process.");
    let child_pid = match nix::sched::clone(Box::new(start_container), &mut stack, flags, None) {
	Ok(pid) => {
	    info!( "Created container with host PID of {}", pid );
	    pid
	},
	Err(e) => panic!("Failed to clone container process: {:?}", e)
    };

    // set up user map for new user namespace
    info!("Setting user namespace mapping");
    update_uid_gid_map(child_pid);

    // we set up a virtual ethernet pair, and allocate IP addresses
    // this is used to allow network communication between host and "container"
    info!("Creating virtual ethernet pair");
    create_veth(handle.clone()).await;
    
    // set host ip address
    info!("Setting host IP to 10.0.0.1/24");
    let host_ip = match IpNetwork::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 24) {
	Ok(ip) => ip,
	Err(e) => panic!("Container: failed to create host IP representation: {:?}", e)
    };
    set_ipaddr("veth0", host_ip, handle.clone()).await;

    // set container ip address
    info!("Setting container IP to 10.0.0.2/24");
    let container_ip = match IpNetwork::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 24) {
	Ok(ip) => ip,
	Err(e) => panic!("Container: failed to create container IP representation: {:?}", e)
    };
    set_ipaddr("veth1", container_ip, handle.clone()).await;
    // TODO set default route to host

    // send veth into container
    info!("Sending container veth into the container namespace");
    send_container_veth(child_pid, handle.clone()).await;
    
    // wait for container process to exit
    info!("Waiting for container process to exit");
    wait_for_container(child_pid).await;
    
    // clean up virtual ethernet devices
    info!("Removing created veth pair" );
    destroy_veth(handle).await;
    Ok(())
}
