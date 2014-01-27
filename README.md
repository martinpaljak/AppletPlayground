Applet Playground
=================

AppletPlayground is an easy method for getting to know JavaCard development. Everything you need to compile and run the open source applets for JavaCard 2.2.2 and load them to GlobalPlatform compatible smart cards for testing with JUnit, for example. Also includes a [Hello World](http://en.wikipedia.org/wiki/Hello_world_program) applet to serve as a starting point of your own applet.

## Included applets
 * MuscleApplet - as was found in martinpaljak/MuscleApplet@d005f36209bdd7020bac0d783b228243126fd2f8 (BSD)
 * CoolKeyApplet - r105 from http://svn.fedorahosted.org/svn/coolkey/trunk/applet (BSD/LGPL2.1)
 * PKIApplet - r65 from http://svn.code.sf.net/p/javacardsign/code/pkiapplet/src (LGPL2.1)
 * OpenPGPApplet - Yubico/ykneo-openpgp@ed928351994b053f3d87ec00ec4a9696d4ff20fe (GPL2)
 * FluffyPGPApplet - FluffyKaon/OpenPGP-Card@545da17f82ff4627758674bbcbb0e602e959d9dd (GPL3)

## What you need ?
 * Unix-like operating system: Linux or OS X
 * A working smart card reader*
 * A JavaCard 2.2.2 card*
 * Eclipse - get from [eclipse.org](http://eclipse.org/downloads/)

## Included extras:
 * [ProGuard 4.11](http://proguard.sourceforge.net/) for shrinking applet codebase (GPL2)
 * [GlobalPlatform](https://github.com/martinpaljak/GlobalPlatform) tool for loading the applets to the card (LGPL3)
 * [jnasmartcardio](https://github.com/jnasmartcardio/jnasmartcardio) for better access to PC/SC smart card readers directly and through javax.smartcardio (CC0 / public domain)
 * JavaCard SDK 2.2.2 (Oracle-owns-you-and-your-grandma license)

## In the pipeline:
 * JavaCard 3.X support
 * Code hardening with http://sourceforge.net/projects/cesta/ (BSD)
 * More flexible build (Grails?)
