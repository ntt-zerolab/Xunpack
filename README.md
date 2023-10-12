Artifacts for our paper, ["Xunpack: Cross-Architecture Unpacking for Linux IoT Malware"](https://dl.acm.org/doi/10.1145/3607199.3607214).

# Bibtex
```
@inproceedings{10.1145/3607199.3607214,
    author = {Kawakoya, Yuhei and Akabane, Shu and Iwamura, Makoto and Okamoto, Takeshi},
    title = {Xunpack: Cross-Architecture Unpacking for Linux IoT Malware},
    year = {2023},
    isbn = {9798400707650},
    publisher = {Association for Computing Machinery},
    address = {New York, NY, USA},
    url = {https://doi.org/10.1145/3607199.3607214},
    doi = {10.1145/3607199.3607214},
    booktitle = {Proceedings of the 26th International Symposium on Research in Attacks, Intrusions and Defenses},
    pages = {471–484},
    numpages = {14},
    keywords = {IoT malware, QEMU, Packer, ISA},
    location = {Hong Kong, China},
    series = {RAID '23}
}
```

# How to use Xunpack/Uunpack/Zunpack

## Build and Run
- Build
```
docker image build -t ubuntu20.04/xunpack:latest .
```
- Run
  - `--privileged` is necessary for the `mount` command used when launch Xunpack.
```
docker run --privileged -v `pwd`:/host -it --rm ubuntu20.04/xunpack
```

## Dump Generation 

### Run Xunpack
```
cd buildroot/x86_64
./start-xunpacker [packed executable]
(ctrl-c to stop)
```

Then, the dumps are stored under the `/tmp/dump/[uuid]` directory.

```
$ ls -l /tmp/dump/b6d7ff50-67f2-4f80-b30c-bd50bb3d2ea3/ | tail -n 10
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:47 S000004f1
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:47 S000004f2
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:47 S000004f3
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:47 S000004f4
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:47 S000004f5
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:47 S000004f6
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:47 S000004f7
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:47 S000004f8
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:47 S000004f9
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:47 S000004fa
```

### Run Uunpack

```
cd scripts
./start-uunpacker.sh [packed executable]
```

Then, the dumps are stored under the `/tmp/dump/[uuid]` directory.

```
$ ls -l /tmp/dump/cb04edb3-df23-4852-9d7d-614124d01331/ | tail -n 10
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:50 00000005
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:50 00000006
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:50 00000007
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:50 00000008
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:50 00000009
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:50 0000000a
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:50 0000000b
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:50 0000000c
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:50 0000000d
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:50 0000000e
```

### Run Zunpack

```
cd scripts
python3 zunpack.py [packed executable] [original executable] [uuid]
```
- Example 
```
python3 zunpack.py /host/bin/upx_3.96/vanilla/x86_64-buildroot-2020.08.3-glibc.upx_3.96 /host/bin/upx_3.96/orig/x86_64-buildroot-2020.08.3-glibc `uuidgen`
```

Then, the dumps are stored under the `/tmp/dump/[uuid]` directory.

```
$ ls -l /tmp/dump/bd48c597-10e1-4e7b-ad60-815f416a697f/ | tail -n 10
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:54 00000005
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:54 00000006
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:54 00000007
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:54 00000008
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:54 00000009
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:54 0000000a
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:54 0000000b
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:54 0000000c
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:54 0000000d
drwxr-xr-x 2 ubuntu ubuntu 4096 Oct  4 23:54 0000000e
```

## Dump Selection (SelectiveDump)
- SelectiveDump is basically necessary only for Xunpack. In the case of Uunpack or Zunpack, you should choose the latest dump in the /tmp/dump/[uuid] directory.
- `SelectiveDumpMP.py` is a multi-process version of `SelectiveDump.py`

```
$ python3 SelectiveDumpMP.py -h
usage: SelectiveDumpMP.py [-h] [--packed PACKED] [--original ORIGINAL] [--delta DELTA] [--text_addr TEXT_ADDR] [--text_size TEXT_SIZE] [--output_dir OUTPUT_DIR] [--size {32,64}] [--sex {1,2}] rootdir

positional arguments:
  rootdir               path to a directory containing dumps

optional arguments:
  -h, --help            show this help message and exit
  --packed PACKED       path to a packed executable
  --original ORIGINAL   path to the original executable
  --delta DELTA         delta for calculation
  --text_addr TEXT_ADDR
                        the address of .text section
  --text_size TEXT_SIZE
                        the size of .text section
  --output_dir OUTPUT_DIR
                        path to the directory to store selected dumps
  --size {32,64}        32bt or 64bit
  --sex {1,2}           1: little endian, 2: big endian
```

- Example
```
$ mkdir /tmp/b6d7ff50-67f2-4f80-b30c-bd50bb3d2ea3_output
$ time python3 SelectiveDumpMP.py --packed /host/bin/upx_3.96/vanilla/x86_64-buildroot-2020.08.3-glibc.upx_3.96 --original /host/bin/upx_3.96/orig/x86_64-buildroot-2020.08.3-glibc --text_addr 0x401000 --text_size 0x80000 --output_dir /tmp/b6d7ff50-67f2-4f80-b30c-bd50bb3d2ea3_output --size  64 --sex 1 /tmp/dump/b6d7ff50-67f2-4f80-b30c-bd50bb3d2ea3/

real	4m13.647s
user	14m22.698s
sys	0m7.692s

$ ls -l /tmp/b6d7ff50-67f2-4f80-b30c-bd50bb3d2ea3_output/ | tail -n 10
-rw-r--r-- 1 ubuntu ubuntu 4096 Oct  5 00:14 0000000000477000-0000000000478000.raw
-rw-r--r-- 1 ubuntu ubuntu 4096 Oct  5 00:14 0000000000478000-0000000000479000.raw
-rw-r--r-- 1 ubuntu ubuntu 4096 Oct  5 00:14 0000000000479000-000000000047a000.raw
-rw-r--r-- 1 ubuntu ubuntu 4096 Oct  5 00:14 000000000047a000-000000000047b000.raw
-rw-r--r-- 1 ubuntu ubuntu 4096 Oct  5 00:14 000000000047b000-000000000047c000.raw
-rw-r--r-- 1 ubuntu ubuntu 4096 Oct  5 00:14 000000000047c000-000000000047d000.raw
-rw-r--r-- 1 ubuntu ubuntu 4096 Oct  5 00:14 000000000047d000-000000000047e000.raw
-rw-r--r-- 1 ubuntu ubuntu 4096 Oct  5 00:15 000000000047e000-000000000047f000.raw
-rw-r--r-- 1 ubuntu ubuntu 4096 Oct  5 00:15 000000000047f000-0000000000480000.raw
-rw-r--r-- 1 ubuntu ubuntu 4096 Oct  5 00:15 0000000000480000-0000000000481000.raw

```
- SelectiveDump usually takes some minutues. If you want to reduce the time, you can increase the number of processes for parallel processing. Currently, SelectiveDumpMP uses 4 processes by default. 

## Code Reconstruction

```
$ python3 elfpack/examples/recon_elf.py -h
usage: ELF Executable Reconstruction [-h] --arch {powerpc,mips64,mips,riscv32,powerpc64,mips64el,sparc64,x86_64,i686,mipsel,sparc,aarch64,arm,riscv64} [--output OUTPUT] rootdir

positional arguments:
  rootdir               directory containing dump files

optional arguments:
  -h, --help            show this help message and exit
  --arch {powerpc,mips64,mips,riscv32,powerpc64,mips64el,sparc64,x86_64,i686,mipsel,sparc,aarch64,arm,riscv64}
                        specify your target arch
  --output OUTPUT       output elf filename
```

- Examples
  - Xunpack (Choose the dump selected by SelectiveDump)
  ```
  $ python3 elfpack/examples/recon_elf.py --arch=x86_64 --output /tmp/b6d7ff50-67f2-4f80-b30c-bd50bb3d2ea3.elf /tmp/b6d7ff50-67f2-4f80-b30c-bd50bb3d2ea3_output/
  ```
  - Uunpack (Choose the latest dump for reconstruction)
  ```
  $ python3 elfpack/examples/recon_elf.py --arch=x86_64 --output /tmp/cb04edb3-df23-4852-9d7d-614124d01331.elf /tmp/dump/cb04edb3-df23-4852-9d7d-614124d01331/0000000e/
  ```
  - Zunpack (Choose the latest dump for reconstruction)
  ```
  $ python3 elfpack/examples/recon_elf.py --arch=x86_64 --output /tmp/bd48c597-10e1-4e7b-ad60-815f416a697f.elf /tmp/dump/bd48c597-10e1-4e7b-ad60-815f416a697f/0000000e/
  ```

## Score Calculation

```
$ python3 score.py -h
usage: score.py [-h] [--text_addr TEXT_ADDR] [--text_size TEXT_SIZE] [--funclist FUNCLIST] [--instlist INSTLIST] [--ignore] src_file dst_file

positional arguments:
  src_file              a binary to compare from
  dst_file              a binary to compared to

optional arguments:
  -h, --help            show this help message and exit
  --text_addr TEXT_ADDR
                        the address of .text section
  --text_size TEXT_SIZE
                        the size of .text section
  --funclist FUNCLIST   (optional) function list
  --instlist INSTLIST   (optional) instruction list
  --ignore              (optional) ignore 0xCC for comparison
```

- Examples
```
cd scripts
$ python3 score.py --text_addr=0x401000 --text_size=0x80000 /tmp/b6d7ff50-67f2-4f80-b30c-bd50bb3d2ea3.elf /host/bin/upx_3.96/orig/x86_64-buildroot-2020.08.3-glibc
...
[-] 480000-481000: matched:4096 ignored:0 score:1.0
matched: 0.9871902465820312
	total_size:524288 matched:517572 ignored:0 func_cnt:0
$ python3 score.py --text_addr=0x401000 --text_size=0x80000 /tmp/cb04edb3-df23-4852-9d7d-614124d01331.elf /host/bin/upx_3.96/orig/x86_64-buildroot-2020.08.3-glibc
...
[-] 480000-481000: matched:4096 ignored:0 score:1.0
matched: 0.9999923706054688
	total_size:524288 matched:524284 ignored:0 func_cnt:0
$ python3 score.py --text_addr=0x401000 --text_size=0x80000 /tmp/bd48c597-10e1-4e7b-ad60-815f416a697f.elf /host/bin/upx_3.96/orig/x86_64-buildroot-2020.08.3-glibc
...
[-] 480000-481000: matched:1247 ignored:0 score:0.304443359375
matched: 0.961711883544921
	total_size:524288 matched:504214 ignored:0 func_cnt:0
```



