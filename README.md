Applet Playground
=================

AppletPlayground is an easy method for getting to know JavaCard development. Everything you need to compile and run the open source applets for JavaCard 2.2.2 and load them to GlobalPlatform compatible smart cards for testing with JUnit or running in an emulated/simulated container. Also includes a [Hello World](http://en.wikipedia.org/wiki/Hello_world_program) applet to serve as a starting point for your own applet. [New features](#in-the-pipeline) coming soon!

## Time to experiment!
![Experiments!](http://www.freevector.com/site_media/preview_images/FreeVector-Evil-Doctor.jpg)
<sub>Mad Genius Vector by Vectorya.com (CC 3.0 Attribution Non-Commercial)</sub>

## Included applets
 * MuscleApplet - as was found in [martinpaljak/MuscleApplet@d005f36209bdd7020bac0d783b228243126fd2f8](https://github.com/martinpaljak/MuscleApplet/commit/d005f36209bdd7020bac0d783b228243126fd2f8) (BSD)
 * CoolKeyApplet - [r105](http://svn.fedorahosted.org/svn/coolkey/!svn/bc/105/trunk/applet/) from http://svn.fedorahosted.org/svn/coolkey/trunk/applet (BSD/LGPL2.1)
 * PKIApplet - [r65](http://svn.code.sf.net/p/javacardsign/code/!svn/bc/65/pkiapplet/src/) from http://svn.code.sf.net/p/javacardsign/code/pkiapplet/src (LGPL2.1)
 * OpenPGPApplet - [Yubico/ykneo-openpgp@ed928351994b053f3d87ec00ec4a9696d4ff20fe](https://github.com/Yubico/ykneo-openpgp/commit/ed928351994b053f3d87ec00ec4a9696d4ff20fe) (GPL2)
 * FluffyPGPApplet - [FluffyKaon/OpenPGP-Card@545da17f82ff4627758674bbcbb0e602e959d9dd](https://github.com/FluffyKaon/OpenPGP-Card/commit/545da17f82ff4627758674bbcbb0e602e959d9dd) (GPL3)
 * YkneoOath - [Yubico/ykneo-oath](https://github.com/Yubico/ykneo-oath/) (GPL3)
 * PassportApplet - http://sourceforge.net/p/jmrtd/code/HEAD/tree/trunk/passportapplet/ (LGPL3)

The following changes have been applied to source code of applets:
 * change of the package name to ```pro.javacard.applets```
 * move of dependant classes to inner classes (as Muscle and CoolKey would conflict, the same "consolidation" was applied to other applets) or otherwise renaming classes.
 * ```GPSystem```->```OPSystem``` 
 * obvious errors and warnings as reported by FindBugs and Coverity (or missing casts to short)
 * code formatting if done automagically by eclipse formatter.

# FEASIBILITY NOTICE
 The above applets and the overall package come "AS-IS". I make no claims about the feasibility, usability, security, correctness whatsoever of the whole package or any of the components. Use at your own risk. Everything here is only for educational purposes.

## What you need ?
 * Unix-like operating system like a recent Linux or OS X with installed JDK 1.7+
 * A working smart card reader* with a driver - preferably a [well-behaving CCID one](http://pcsclite.alioth.debian.org/ccid/section.html)
 * A JavaCard 2.2.2 card*
   * [a list of webshops and compatible JavaCards](https://github.com/martinpaljak/GlobalPlatform/wiki/TestedCards)
 * Eclipse - get from [eclipse.org](http://eclipse.org/downloads/)

\* you can work with source code without a card and reader, but for actual testing having one is preferable.

## Included extras:
 * [ProGuard 4.11](http://proguard.sourceforge.net/) for shrinking applet codebase (GPL2)
 * [GlobalPlatform](https://github.com/martinpaljak/GlobalPlatform) tool for loading the applets to the card (LGPL3)
 * [jnasmartcardio](https://github.com/jnasmartcardio/jnasmartcardio) for better access to PC/SC smart card readers directly and through [javax.smartcardio](http://docs.oracle.com/javase/7/docs/jre/api/security/smartcardio/spec/javax/smartcardio/package-summary.html) (CC0 / public domain)
 * JavaCard SDK 2.2.2 (Oracle-owns-you-and-your-grandma license)

## How to use
 * Import this project into Git and execute the "toys" ANT target. 
 * Ore use command line and issue ```ant clean toys```
 * Use the included [GlobalPlatform utility](https://github.com/martinpaljak/GlobalPlatform#usage) to load any of the generated applets (```.cap``` files)to a card

## In the pipeline:
 * Generic
   * JavaCard 3.0.1/3.0.4 as well as JavaCard 2.2.1 support
   * Automatic code hardening with http://sourceforge.net/projects/cesta/ (BSD)
   * Card simulation with [jCardSim](https://github.com/licel/jcardsim)* (Apache 2.0) <sub>currently only supports JavaCard 2.2.1 :(</sub>
 * More applets:
   * BTChipApplet - https://github.com/btchip/btchipJC (AGPL3) <sub>Depends on JavaCard 3 support</sub>
   * [FakeEstEID](https://github.com/martinpaljak/AppletPlayground/wiki/FakeEstEID) - Estonian ID-card compatible applet (MIT)
   * EchoApplet, TraceApplet, RandomApplet, StorageApplet
   * If you want to see more applets in the build set, file an issue with link!
 * More flexible build (Grails?)

## Contact
 * martin@martinpaljak.net
 * For improvements file an issue. Better yet - a pull request!
 * General chat at [OpenKMS Google forum](https://groups.google.com/forum/#!forum/openkms)

## Similar projects
 * https://minotaur.fi.muni.cz:8443/~xsvenda/docuwiki/doku.php?id=public:smartcard:javacardcompilation
