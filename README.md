Applet Playground
=================

AppletPlayground is an easy method for getting to know JavaCard development. Everything you need to compile and run the open source applets for JavaCard 2.2.2 and load them to GlobalPlatform compatible smart cards for testing with JUnit, for example. Also includes a [Hello World](http://en.wikipedia.org/wiki/Hello_world_program) applet to serve as a starting point of your own applet.

## Time to experiment!
![Experiments!](http://www.freevector.com/site_media/preview_images/FreeVector-Evil-Doctor.jpg)

## Included applets
 * MuscleApplet - as was found in [martinpaljak/MuscleApplet@d005f36209bdd7020bac0d783b228243126fd2f8](https://github.com/martinpaljak/MuscleApplet/commit/d005f36209bdd7020bac0d783b228243126fd2f8) (BSD)
 * CoolKeyApplet - [r105](http://svn.fedorahosted.org/svn/coolkey/!svn/bc/105/trunk/applet/) from http://svn.fedorahosted.org/svn/coolkey/trunk/applet (BSD/LGPL2.1)
 * PKIApplet - [r65](http://svn.code.sf.net/p/javacardsign/code/!svn/bc/65/pkiapplet/src/) from http://svn.code.sf.net/p/javacardsign/code/pkiapplet/src (LGPL2.1)
 * OpenPGPApplet - [Yubico/ykneo-openpgp@ed928351994b053f3d87ec00ec4a9696d4ff20fe](https://github.com/Yubico/ykneo-openpgp/commit/ed928351994b053f3d87ec00ec4a9696d4ff20fe) (GPL2)
 * FluffyPGPApplet - [FluffyKaon/OpenPGP-Card@545da17f82ff4627758674bbcbb0e602e959d9dd](https://github.com/FluffyKaon/OpenPGP-Card/commit/545da17f82ff4627758674bbcbb0e602e959d9dd) (GPL3)

The following changes have been applied to source code of applets:
 * change of the package name
 * move of dependant classes to inner classes (as Muscle and CoolKey would conflict, the same "consolidation" was applied to other applets)
 * GPSystem->OPSystem 
 * missing casts to short
 * code formatting

# FEASIBILITY NOTICE
 The above applets and the overall package come "as-is". I make no claims about the feasibility, usability, security, correctness whatsoever of the whole package or any of the components. Use at your own risk. Everything here is only for educational purposes.

## What you need ?
 * Unix-like operating system like a recent Linux or OS X
 * A working smart card reader* with a driver - preferably a [well-behaving CCID one](http://pcsclite.alioth.debian.org/ccid/section.html)
 * A JavaCard 2.2.2 card*
 * Eclipse - get from [eclipse.org](http://eclipse.org/downloads/)

\* you can work with source code without a card and reader, but for actual testing having one is preferable.

## Included extras:
 * [ProGuard 4.11](http://proguard.sourceforge.net/) for shrinking applet codebase (GPL2)
 * [GlobalPlatform](https://github.com/martinpaljak/GlobalPlatform) tool for loading the applets to the card (LGPL3)
 * [jnasmartcardio](https://github.com/jnasmartcardio/jnasmartcardio) for better access to PC/SC smart card readers directly and through [javax.smartcardio](http://docs.oracle.com/javase/7/docs/jre/api/security/smartcardio/spec/javax/smartcardio/package-summary.html) (CC0 / public domain)
 * JavaCard SDK 2.2.2 (Oracle-owns-you-and-your-grandma license)

## How to use
 * Import this project into Git and execute the "toys" ANT target
 * Ore use command line and issue "ant clean toys"
 * Use the included GlobalPlatform utility to load applets to card

## In the pipeline:
 * JavaCard 3.X support
 * Code hardening with http://sourceforge.net/projects/cesta/ (BSD)
 * More flexible build (Grails?)
 * ykneo-oath - https://github.com/Yubico/ykneo-oath/ (GPL)
 * BTChipApplet - https://github.com/btchip/btchipJC (AGPL3)

## Contact
 * martin@martinpaljak.net
 * For improvements file an issue!
