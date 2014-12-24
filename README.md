Ghetto Unlock
=============

Lollipop trust agent sample. See post below for details:

http://nelenkov.blogspot.com/2014/12/dissecting-lollipops-smart-lock.html

** How to build **

Copy to ```packages/apps/``` in AOSP tree. Drop Spongy Castle lightweight API 
jar in ```libs/``` and adjust ```Android.mk``` accordingly (tested with  
```sc-light-jdk15on-1.47.0.2.jar```). Run ```mm``` to build.

