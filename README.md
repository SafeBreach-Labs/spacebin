# Spacebin

Spacebin is a proof-of-concept malware that exfiltrates data (from air-gapped-like environments) via triggering AV on the endpoint and then communicating back from the AV's cloud component.

It was released as part of the [THE ADVENTURES OF AV AND THE LEAKY SANDBOX](https://www.blackhat.com/us-17/briefings.html#the-adventures-of-av-and-the-leaky-sandbox) talk given at BlackHat USA 2017 conference and DEF CON 25 by Itzik Kotler and Amit Klein from [SafeBreach Labs](http://www.safebreach.com).

Slides are availble [here](https://www.blackhat.com/docs/us-17/thursday/us-17-Kotler-The-Adventures-Of-Av-And-The-Leaky-Sandbox.pdf) and White paper is avialble [here](https://www.blackhat.com/docs/us-17/thursday/us-17-Kotler-The-Adventures-Of-Av-And-The-Leaky-Sandbox-wp.pdf)

### Version
0.1.0

### What's Inside?
1. bingroundctrl is a directory with the server-side code.

2. binrocket is a directory with client-side code. It's the Python script that generates a rocket (i.e. C file that packs the binary satellite)

3. binsatellite is a directory with more client-side code (i.e. Visual Studio 2015 Solution). It's the actual binary satellite.

### Instructions

1. There's a batch file called go.bat that does pretty much everything on the client side aspect. It takes optional command line argument (i.e. go.bat "Secret Data") that will be the payload. If not, "Hello, world" is the default.

2. The go.bat assumes two things: That you're running it from "Developer Command Prompt" (i.e. CL is in your PATH) and that you're running it from the spacebin root directory. The latter is important because it uses relative-path to "reference" binsatellite Release binary.

3. The results are rendered in a Web UI that is hosted on: http://YOUR_SITE:8080 the username is YOUR_USERNAME and the password is YOUR_PASSWORD the code this website is inside bingroundctrl and it's a mixture of: tailon (Python app), nginx, tail, grep etc.

4. To test that everything works as expected:

open the URL, login to the app. Afterward run go.bat with a string (i.e. go.bat "Secret Secret") and see that it appears on the Web UI.


License
----

BSD 3-Clause



