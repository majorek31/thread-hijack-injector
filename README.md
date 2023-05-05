# thread-hijack-injector
## thread hijacking injcetion technique.
This technique of dll injection uses context switching to hijack the main thread.
After main thread has been hijacked we allocate enough space for the shellcode and path for dll that we are going to inject.
Then we replace original EIP of the thread to our shellcode, after that we resume it's work and watch the magic happening.
