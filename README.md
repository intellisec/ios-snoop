# False Sense of Security: A Study on the Effectivity of Jailbreak Detection in Banking Apps

People increasingly rely on mobile devices for banking transactions
or two-factor authentication (2FA) and thus trust in the security
provided by the underlying operating system. Simultaneously, jailbreaks
gain tremendous popularity among regular users for customizing their
devices. In this project, we show that both do not go well together:
Jailbreaks remove vital security mechanisms, which are necessary to
ensure a trusted environment that allows to protect sensitive data, such
as login credentials and transaction numbers (TANs). We find that all
but one banking apps, available in the iOS App Store, can be fully
compromised by trivial means without reverse-engineering, manipulating
the app, or other sophisticated attacks.
Our study assesses the current state of security of banking apps and
pleads for more advanced defensive measures for protecting user data.

# Overview of Banking Apps

The following table summarizes our findings: For all but one of 33
banking apps (one of the test subjects has been discontinued by now)
sensitive user data has been successfully intercepted. However, only
18 of these banking apps actually make use of mechanisms for
Jailbreak detection. 

<img src="https://dev.sec.tu-bs.de/ios/jbd-overview.svg" width="700">

For details on the specific versions of the apps, please consult
the [conference publication](https://dev.sec.tu-bs.de/ios/2019-eurosp.pdf).

# Code
This repository contains a tweak for analyzing jailbreak detection
mechanisms of apps installed on a jailbroken iOS device. All results
will be send to the DiOS Backend.  
The tweak also includes different types of keyloggers (for for
standard UI of apps, webviews and one for a custom keyboard of one
app).

### Dependencies
* [theos](https://github.com/theos/theos/wiki/Installation) (with `$THEOS` set to the installation directory)
* [DiOS](https://github.com/DiOS-Analysis/DiOS/wiki/Initial-Setup)
* [Cydia Substrate](http://www.cydiasubstrate.com/)

### Install
```
git clone https://github.com/device-sec/ios-snoop.git
cd ios-snoop
export $THEOS_DEVICE_IP=<your_device_ip>
export $THEOS_DEVICE_PORT=22
make package install
```

# Publication
A detailed description of our work is going to be presented at the
4th IEEE European Symposium on Security and Privacy (EuroS&P 2019)
in June 2019. If you would like to cite our work, please use the
reference as provided below:

```
@InProceedings{KelHorRieWre19,
  author =    {Ansgar Kellner and Micha Horlboge and Konrad Rieck and
               Christian Wressnegger},
  title =     {False Sense of Security: A Study on the Effectivity of
               Jailbreak Detection in Banking Apps},
  booktitle = {Proc. of the {IEEE} European Symposium on Security and
               Privacy ({EuroS\&P})},
  year =      2019,
  month =     jun,
  day =       {17.--19.}
}
```

A preprint of the paper is available [here](https://dev.sec.tu-bs.de/ios/2019-eurosp.pdf).
