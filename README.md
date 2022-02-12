# PPL_Sandboxer

Original Blog: https://elastic.github.io/security-research/whitepapers/2022/02/02.sandboxing-antimalware-products-for-fun-and-profit/article/

I made this as an attempt of a PoC to sandbox AV products by reducing their security tokens to an "untrusted level". Making it so they cannot interact with the host system.
I was successful in a few ways, but failed in others. My goal was to make a stealthy version (using native APIs and system calls to bypass hooking).
I finished a way to set the token levels to untrusted for targeted processes, even PPLs. However, when I call this program on vsserv.exe (BitDefenders) security service, it never returns after lowering the security tokens access level.
It also causes the computers CPU to go into hyperdrive, this makes me believe BitDefender has something in place that prevents it from completeing fully.

Anyway, if you come across this and decide you want to take a shot at it, i keep some comments that may help and function calls in comments that i used to try differetn methods to acheive the same goal.

Must be ran from high integrity process.

Here is a video of the program working.

https://user-images.githubusercontent.com/41178870/153692845-9d6ae64d-0562-43ee-909a-65db6a67e4c2.mp4

