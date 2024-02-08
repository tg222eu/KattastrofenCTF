# KattastrofenCTF



Instructions translated: A civil servant on a protected-worthy goverment has a weakness of picture of kittens. In eagerness to watch these kind of pictures, has the person accidentally uploaded somthing that was not good. Not at all good. We suspect that malicious code has been used to exfiltrate top secret documents from the goverment. Analyze the networktraffic to figure out what has happend

The challenge contain 3 flags that has the form "flagga[1-3]{[a-zå-ö_!]+}"

Immediately when opening up the PCAP I notice among the first packets there are HTTP objects. I extract the files onto my computer and start investigating. The Kittenz.zip is proctected with a password "hunter2" which was found in %5c file. Once extracted flag file and open it the first flag is revealed.

Flag flagga1{klassiska_lösenord_för_100}



