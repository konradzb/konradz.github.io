---
layout: post
tags: [soopr, config]
---


# DLL Injection: A Comprehensive Security Perspective

I created this short paper to sumerize my knowledge about DLL and DLL Injection in one place. Its much easier to exploit something from time to time when you don't have to remind every detail again and agian :). There is no fancy stuff, the idea was to create geenral guide to help myself when I came across DLL Injection in the future. For example on Windows we have User32.dll, which exports functions related to user interface. 

Applications can be devided into multiple modules, each module have its seperate DLL file, which is loaded seperatly when main application (.exe file) requires it. It is more eficient for system to maintain mudular application, but I think more important is fact, that is also easier to maintain applications code when its devided into modules.

## 1. What is a DLL?

As we can read on [oficial microsoft page](https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/dynamic-link-library#more-information) - "a DLL is a library that contains code and data that can be used by more than one program at the same time". It's more eficient to place your code in DLL when you know it will be used in multiple places. Unlike static libraries that are embedded into an executable at compile time, DLL will be loaded when particular function is called inside the code.


### 1.2 Structure and Portable Executable (PE) Format

Structure of Portable Executable (PE) is quite complicated and I am not going to copy the inforamtion from oficial microsoft website, you can find [more information there](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format). 
Great visualization was done in the picture below, where simple.exe was described, however the structure is similar to the DLL file 

![pic](../_screenshots/pe101.png)


Understading of how the PE format is build and works is whole other topic. 0xRick on his blog explained in details how PE format is stucture so you can find more information there - [Dive into PE Format](https://0xrick.github.io/win-internals/pe1/)

---

## 2. Detection Mechanisms: Procmon and Process Explorer

### 2.1 Process Monitor (Procmon)

**Process Monitor (Procmon)** is a real-time Windows system monitoring tool from Sysinternals that captures system calls, registry operations, and file I/O operations. For DLL-related troubleshooting:

**Detecting Missing DLLs**:
Procmon captures all events that happens on the system, which can be overlaming at first, when we first time open the program. That is why there is function for filtering events, to reduce the number of displayed rows. 

As an example, we will inwestigate service that is running with SYSTEM privileges.

#TODO Example Create example in the virtual machine, to the screnshoots etc.

### 2.2 Process Explorer

**Process Explorer**, another Sysinternals tool, provides a hierarchical view of running processes with detailed information about loaded DLLs and open files. For DLL analysis:

#TODO compare it on an created example with the process monitor

---

## 3. DLL Injection: Mechanism and Execution

### 3.1 Definition

**DLL Injection** is a technique used to introduce a Dynamic Link Library into the address space of a running process, thereby altering the behavior of that process without modifying its original code. The injected DLL executes with the same privileges as the target process and can perform arbitrary operations within that context.

### 2.2 How DLL Injection Works - General overview

The DLL injection process follows a systematic approach:

1. **Process Identification**: 

3. **DLL Path Injection**: The path to the malicious DLL is written into the allocated memory within the target process.

4. **Thread Creation**: A remote thread is created within the target process using `CreateRemoteThread()`, instructing it to load the DLL via `LoadLibrary()` or similar functions.

5. **Code Execution**: The injected DLL's `DllMain` function is called automatically by the Windows loader, executing the malicious payload.


---

## 3. System DLLs (LOLBINs) vs Custom Application DLLs

### 3.1 System DLLs and Living-Off-The-Land Binaries (LOLBINs)



### 3.2 Custom Application DLLs


---



## 5. DLL Sideloading: The Stealthy Injection Vector

### 5.1 Definition and Mechanism

**DLL Sideloading**, also known as **DLL search-order hijacking**, is a technique where an attacker places a malicious DLL in the same directory as a legitimate, signed executable. When the executable launches, Windows searches for required DLLs following a specific search order:

1. The directory from which the application was loaded (first priority)
2. The system directory
3. The Windows directory
4. The directories in the PATH environment variable

By exploiting this search order, the attacker's malicious DLL is found and loaded instead of the legitimate system DLL.

### 5.2 Why DLL Sideloading is Effective

**Evasion advantages**:
- The process tree shows execution of a legitimate, signed binary (not malware)
- The parent process is often trusted
- Signed binaries face less scrutiny from security solutions
- No registry modifications or suspicious process creation
- Appears as normal application behavior

**Real-world example**: An attacker copies both a legitimate `explorer.exe` and a malicious `shell32.dll` to a user-writable directory. When the user executes the legitimate binary from that location, it loads the malicious DLL first, executing the attacker's payload while the legitimate application either crashes or continues normally (depending on implementation).


---

## 6. DLL Proxying: Advanced Stealthy Evasion

### 6.1 Definition

**DLL Proxying** is an advanced technique combining DLL sideloading with **export forwarding**. Instead of simply loading a malicious DLL, the proxy DLL forwards all exported function calls to the legitimate original DLL while executing a malicious payload. This ensures the target application functions normally, avoiding crashes or suspicious behavior.

### 6.2 How DLL Proxying Works

The process involves creating a wrapper DLL that:
1. Exports all the same functions as the original DLL
2. Forwards function calls to the legitimate DLL
3. Executes malicious code in its `DllMain` entry point

**Export Forwarding Mechanism**: Instead of containing actual function implementations, the Export Address Table contains forwarders—strings that redirect to functions in another DLL. For example:

```
EXPORTS
    GetFileVersionInfoA = SHCore.dll.GetFileVersionInfoA
    GetFileVersionInfoW = SHCore.dll.GetFileVersionInfoW
    CommandLineToArgvW = SHCore.dll.CommandLineToArgvW
```

When an application calls `GetFileVersionInfoA`, the Windows loader automatically redirects the call to `SHCore.dll.GetFileVersionInfoA`.

### 6.3 Why DLL Proxying is Necessary

**Without Proxying**:
- Target application expects specific function exports
- If the malicious DLL doesn't provide these functions, the application crashes
- Crash is suspicious and easily detected
- Attacker's presence becomes obvious

**With Proxying**:
- All expected functions are available (forwarded to legitimate DLL)
- Application functions normally
- Malicious payload executes silently in the background
- Behavior appears completely legitimate to users and security tools

**Historical precedent**: The infamous Stuxnet malware used DLL proxying extensively to maintain stealth while executing its mission.

---

## 7. DLL Compilers and Build Tools


## 8. How to Compile Your Own DLL

### 8.1 Complete Example Using Visual Studio



## 9. DLL Loading: Static vs Dynamic Loading

### 9.1 Static (Load-Time) Linking



## 10. DLL Main Limitations and Best Practices

### 10.1 DllMain Entry Point



---

## Conclusion



## References

- [What is a DLL](https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/dynamic-link-library)
- [PE Format - documentation](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [PE Format - picture](https://github.com/corkami/pics/blob/master/binary/pe101/pe101.png)
- [Dive into PE Format](https://0xrick.github.io/win-internals/pe1/)


### TODO:
- what is DOS mode?