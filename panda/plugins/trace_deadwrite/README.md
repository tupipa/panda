# How to Run PANDA with trace_deadwrite plugin

## 1. Docker Environment

### 1.1 Install Docker
For simplicity, it is suggested to use Docker platform to test PANDA. 
Please install latest docker-ce version from here: https://docs.docker.com/engine/installation/

For ubuntu 16.04: https://docs.docker.com/engine/installation/linux/docker-ce/ubuntu/#os-requirements

### 1.2 Prepare a work directory (Optional)

You might want to keep all your work saved at some place. So create a directory for your work. Say **/home/test/panda-work**.

### 1.3 Run container:

Next, you are able to download the whole experimental environment with just one command:

`docker run -t -i -p 5915:5915 --privileged --name panda -v **/home/test/panda-work**:/root/lab tupipa/panda-net`

Some explainations: 
`-p 5915:5915` forwards all the traffic to a port 5915 on host to oort 5915 on the container. This is used for VNC access of an qemu virtual machine. 
`--privileged` allows the container to run qemu with network device, avoiding errors of QEMU's "-net tap" option.
`-v **/home/test/panda-work**:/root/lab` will share the host directory /home/test/panda-work with directory `/root/lab` inside the container.
So that you can save files to /root/lab and keep it forever even when you remove your container. 
If you didn't set up the work dir in setp 1.2, you can just ignore this option.

## 2. Run PANDA and Record Execution

### 2.1 prepare system image to run on QEMU.

PANDA is an extension to QEMU, a virtual machine monitor. So to run it, you need to give PANDA a virtual machine image to run.
For example, you can download Debian image from here: https://people.debian.org/~aurel32/qemu/amd64/.

This plugin is tested under https://people.debian.org/~aurel32/qemu/amd64/debian_wheezy_amd64_standard.qcow2, you can get it via:
wget by running inside container:
```
cd /root/lab/
mkdir images
wget https://people.debian.org/~aurel32/qemu/amd64/debian_wheezy_amd64_standard.qcow2 
```

### 2.2 download and compile the latest panda

```
cd /root/lab
git pull https://github.com/panda
cd panda/
mkdir build/
cd build/
../build.sh
```

### 2.3. Run PANDA/QEMU and recording

You can run PANDA just like how to run QEMU. 
For example, after built, the QEMU executable will be available in /root/lab/panda/build/, 
then you can run the downloaded Debian image with the following command:
```
/root/lab/panda/build/x86_64-softmmu/qemu-system-x86_64 -net tap -net nic -m 512 /root/lab/images/debian_wheezy_amd64_standard.qcow2 -vnc :15 -monitor stdio
```

#### run record command to record all executions

Once the QEMU started, it will promote to monitor command line interface:
```
QEMU 2.8.50 monitor - type 'help' for more information
(qemu) begin_record [record_file_name] //**this command starts recording, execution record will be written to [record_file_name]-rr-snp, and [record_file_name]-rr-nondet.log **
(qemu)              // **now you can do something inside the Debian guest machine, everything inside will recorded.**
(qemu) end_record // **now the recording ends
```

### 2.4 Access Guest VM Terminal

You can access guest either by VNC viewer, or by ssh inside the container. 
#### VNC access on host or container
You can access the guest VM with 5915 port on your host. 
For example, if your host is Ubuntu/Linux, you can run `vncviewer localhost:5

#### SSH access
Inside container, the guest VM has an ip address of 192.168.53.89. 
In order to access the terminal via ssh, you need to install and start ssh server on the guest VM (via VNC access).

For example, after you installed ssh server and created user name "test", you can do the following to access:

```
docker exec -ti panda bash //**this command allows you to login inside the container**
ssh root@192.168.53.89     // **ssh to qemu guest vm**
```

### 2.5 Preparing the Guest VM

#### 2.5.1 Kernel Symbol Info for PANDA

We need OSI plugins in PANDA to be able to do instrospection for kernel structures.
Please follow the tutorial [here](https://github.com/tupipa/panda/blob/deadspyCCT/panda/plugins/osi_linux/USAGE.md)

After you got the guest symbol info. Append it to the file `panda/plugins/osi_linux/kernelinfo.conf` and **rebuild PANDA**.

#### 2.5.2 Kernel Symbol Info for trace_deadwrite plugin

For guest vm kernel sysmbols and each application we want to monitor, we need to set up the kernel symbol file path. 
`trace_deadwrite` read all the file paths from one file. 
For example, the benchmark of `ko_dead_array_test` has all its related symbol file info stored at:
`https://github.com/tupipa/deadwriteBenchmark/ko_dead_array_test/symInfo.text`:
```
kernelspace:/root/deadwriteBenchmark/ko_dead_array_test/k_array_test.ko
offset:0xffffffffa01c0000
size:12475
sysmap:/root/out-panda/images/debian_wheezy_amd64/System.map-3.2.0-4-amd64
```

Line 1 to 3 indicates the kernel module information: 
`kernel module executable with symbols in it`; 
`the offset of the kernel module inside kernel`; and
`the size of the kernel module`.
Those info could be got while the kernel module is loaded into guest kernel. 
A simple script can be used to read them: [run.sh](https://github.com/tupipa/deadwriteBenchmark/blob/master/ko_dead_array_test/run.sh)

Line 4 indicates the file path of the kernel symbol for Guest VM. 
We need to copy this file to be available in side the container.
You can put it in the same direcotry with the image file of the Guest VM.

## 3. Run PANDA and Replay Execution with trace_deadwrite

Full Command
```
/root/lab/panda/build/x86_64-softmmu/qemu-system-x86_64 -net user -net nic -m 512  -monitor stdio -replay [record_file_name] -os linux-64-deb7x64 -panda osi -panda osi_linux -panda asidstory -panda callstack_instr -panda trace_deadwrite:symInfo="/root/lab/deadwriteBenchmark/ko_dead_array_test/symInfo.text",proc="insmod",is_kernel_module
```

Options:

```
-net user -net nic -m 512  -monitor stdio
```
```
-replay [record_file_name] 
```
```
-os linux-64-deb7x64 
-panda osi -panda osi_linux -panda asidstory -panda callstack_instr 
```
```
-panda trace_deadwrite:symInfo="/root/lab/deadwriteBenchmark/ko_dead_array_test/symInfo.text",proc="insmod",is_kernel_module
```

After finished replaying, the dead write report is written to file 'trace_deadwrite_test_deadwrite_kernel.txt' in the current directory.

