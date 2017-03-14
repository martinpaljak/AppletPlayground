# Applet Playground [![Build Status](https://travis-ci.org/martinpaljak/AppletPlayground.svg?branch=master)](https://travis-ci.org/martinpaljak/AppletPlayground)

AppletPlayground is an educational repository for getting to know JavaCard development by learning from existing open source software.

It includes various open source applets from the internet, bundled into ready to use package. Everything you need to edit, compile and load the applets to real JavaCard-s or test with an emulator.



## Time to experiment!
![Experiments!](http://www.freevector.com/site_media/preview_images/FreeVector-Evil-Doctor.jpg)
<sub>Mad Genius Vector by Vectorya.com (CC 3.0 Attribution Non-Commercial)</sub>

## Included applets
 * MuscleApplet - as was found in [martinpaljak/MuscleApplet@d005f36209bdd7020bac0d783b228243126fd2f8](https://github.com/martinpaljak/MuscleApplet/commit/d005f36209bdd7020bac0d783b228243126fd2f8) (BSD)
 * CoolKeyApplet - [r105](http://svn.fedorahosted.org/svn/coolkey/!svn/bc/105/trunk/applet/) from http://svn.fedorahosted.org/svn/coolkey/trunk/applet (BSD/LGPL2.1)
 * PKIApplet - [r65](http://svn.code.sf.net/p/javacardsign/code/!svn/bc/65/pkiapplet/src/) from http://svn.code.sf.net/p/javacardsign/code/pkiapplet/src (LGPL2.1)
 * OpenPGPApplet - [Yubico/ykneo-openpgp@25e3f74](https://github.com/Yubico/ykneo-openpgp) (GPL2)
 * FluffyPGPApplet* - [FluffyKaon/OpenPGP-Card@545da17f82ff4627758674bbcbb0e602e959d9dd](https://github.com/FluffyKaon/OpenPGP-Card/commit/545da17f82ff4627758674bbcbb0e602e959d9dd) (GPL3)
 * YkneoOath - [Yubico/ykneo-oath](https://github.com/Yubico/ykneo-oath/) (GPL3)
 * PassportApplet - http://sourceforge.net/p/jmrtd/code/HEAD/tree/trunk/passportapplet/ (LGPL3)
 * BTChip* - [LedgerHQ/btchipJC](https://github.com/LedgerHQ/btchipJC) (AGPL3)
 * NDEF - [slomo/ndef-javacard](https://github.com/slomo/ndef-javacard) (DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE :))
 * BeID* - [r62](https://code.google.com/p/eid-quick-key-toolset) (LGPL)
 * OpenEMV - [r3](svn://svn.code.sf.net/p/openemv/code/trunk) from svn://svn.code.sf.net/p/openemv/code/trunk (LGPL2)
 * ISOApplet - [philipWendland/IsoApplet](https://github.com/philipWendland/IsoApplet) (GPL3)
 * DriversLicense* [r175](svn://svn.code.sf.net/p/isodl/code/) from svn://svn.code.sf.net/p/isodl/code/ (LGPL2)
 * PLAID - [DHS Reference Implementation](http://www.humanservices.gov.au/corporate/publications-and-resources/plaid/reference-implementation-dhs) ([License](http://www.humanservices.gov.au/corporate/publications-and-resources/plaid/licence-terms))
 * AlgTest
 * readertest - [r3223](https://anonscm.debian.org/viewvc/pcsclite/trunk/HandlerTest/JavaCard/src/org/debian/alioth/pcsclite/readertest/readertest.java?view=markup&pathrev=3223)
 * javacard-ndef - [promovicz/javacard-ndef@e3b271d](https://github.com/promovicz/javacard-ndef) (GPL)
 * GidsApplet [vletoux/GidsApplet@f467573](https://github.com/vletoux/GidsApplet) (GPL3)
 * SatoChipApplet [Toporin/SatoChipApplet@0f34d40](https://github.com/Toporin/SatoChipApplet) (AGPL3)
 * HelloWorldApplet [licel/jcardsim@70294c3d48acccd419d6858d824c63bdbd14a355](https://github.com/licel/jcardsim/blob/70294c3d48acccd419d6858d824c63bdbd14a355/src/main/java/com/licel/jcardsim/samples/HelloWorldApplet.java) (Apache 2.0)

Note: applets marked with * have obvious blocking errors (missing casts from int to short for 2.2.X target) removed from source.

# FEASIBILITY NOTICE
The above applets and the overall package comes "AS-IS". I make no claims about the feasibility, usability, security, correctness whatsoever of the whole package or any of the components. Use at your own risk. Everything here is only for educational purposes.

## What you need ?
 * Preferrably a Unix-like operating system like a recent Linux or OS X with installed JDK 1.7+ (but works also with Windows)
 * A working smart card reader* with a driver - preferably a [well-behaving CCID one](http://pcsclite.alioth.debian.org/ccid/section.html)
 * A JavaCard card* (v2.2.2 or better)
   * [a list of webshops and compatible JavaCards](https://github.com/martinpaljak/GlobalPlatform/wiki/TestedCards)
 * Eclipse - get from [eclipse.org](http://eclipse.org/downloads/)

\* you can work with source code without a card and reader, but for actual testing having one is preferable.

## Included extras:
 * [ant-javacard](https://github.com/martinpaljak/ant-javacard) - for building CAP files (MIT)
 * [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro) - for loading the applets to the card (LGPL3)
 * JavaCard SDK 2.2.2 and 3.0.3 (Oracle-owns-you-and-your-grandma license)

## How to use
 * Import this project from Git (or directly into Eclipse) and execute the "toys" ANT target.
 * Or use command line and issue `ant`
 * Use the included [GlobalPlatform utility](https://github.com/martinpaljak/GlobalPlatform#usage) to load any of the generated applets (```.cap``` files) to a card

## In the pipeline:
 * Automatic code hardening with http://sourceforge.net/projects/cesta/ (BSD)
 * Automatic card simulation with [vJCRE](https://github.com/martinpaljak/vJCRE#import-projavacardvre) (MIT/GPL)
 * Automatic card simulation with [jcardsim](http://jcardsim.org)

## Contact
 * martin@martinpaljak.net
 * For improvements file an issue. Better yet - a pull request!
