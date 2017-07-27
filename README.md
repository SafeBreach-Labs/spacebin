# THIS IS TEMP README

What's in the package?

1. bingroundctrl is a directory with the server-side code.

2. binrocket is a directory with client-side code. It's the Python script that generates a rocket (i.e. C file that packs the binary satellite)

3. binsatellite is a directory with more client-side code (i.e. Visual Studio 2015 Solution). It's the actual binary satellite.

Instructions:

1. I've created a batch file called go.bat that does pretty much everything on the client side aspect. It takes optional command line argument (i.e. go.bat "Hello Amit Klein") that will be the payload. If not, "Hello, world" is the default.

2. The go.bat assumes two things: you're running it from "Developer Command Prompt" (i.e. CL is in your PATH) and that you're running it from the spacebin root directory. The latter is important because it uses relative-path to "reference" binsatellite Release binary.

3. The results are rendered in a Web UI that is hosted on: http://<YOUR SITE>:8080 the username is <YOUR_USERNAME> and the password is <YOUR_PASSWORD> the code this website is inside bingroundctrl and it's a mixture of: tailon (Python app), nginx, tail, grep etc.

4. To test that everything works as expected:

open the URL, login to the app. Afterward run go.bat with a string (i.e. go.bat "I am Amit Klein") and see that it appears on the Web UI.

