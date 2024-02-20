# Kattastrofen CTF
<br>
This is a CTF challange made by FRA which can be found here https://challenge.fra.se/
<br>
<br>
<br>

![alt text](https://github.com/tg222eu/KattastrofenCTF/blob/main/pictures/Instructions.JPG)<br>

Instructions translated: A civil servant on a protected-worthy goverment has a weakness of picture of kittens. In eagerness to watch these kind of pictures, has the person accidentally uploaded somthing that was not good. Not at all good. We suspect that malicious code has been used to exfiltrate top secret documents from the goverment. Analyze the networktraffic to figure out what has happend

The challenge contain 3 flags that has the form "flagga[1-3]{[a-zå-ö_!]+}"

## Flag 1:

![alt text](https://github.com/tg222eu/KattastrofenCTF/blob/main/pictures/HTTPpackets.JPG)<br>

Immediately when opening up the PCAP I notice among the first packets there are HTTP objects. I extract the files onto my computer and start investigating. The Kittenz.zip is proctected with a password "hunter2" which was found in %5c file. Once extracted flag file and open it the first flag is revealed.

![alt text](https://github.com/tg222eu/KattastrofenCTF/blob/main/pictures/flagga1.JPG)<br>

Flag: flagga1{klassiska_lösenord_för_100}

## Flag 2:

The zip file also contains another interesting file, kitten-3.jpg which cannot be opened as a picture. When investigating in notepad there is a script inside that steals the document folder in Linux into a exfil.tar file, then extract size and md5 and put it in the exfil.dat, encrypt the exfile.tar with base64 and XOR that uses a key variable in the file.

The script also creates a mjau file that has instructions encrypted with base64 which can be read by decrypting with base64 or can be read by running the script in Linux that creates a partly readable file named mjau. There are two clues that are interesting. One is DNSCat is mentioned which also builds a DNS request/response, the other mention "cutekittenzz.xyz". When we look into the pcap we can see there is a lot of DNS request which contains cutekittenzz.xyz. Further research reveales this might be a DNS exfiltration using DNSCat2. Its likely a document folder has been sent through the DNS which we will try to extract and investigate.

![alt text](https://github.com/tg222eu/KattastrofenCTF/blob/main/pictures/tshark.JPG)<br>

We need to extract the interesting field values from all the DNS requests in the pcap, which contain the data sent by the malicious actor. This can be done by using tshark command below.
```
tshark -Y "dns and ip.src == 10.0.0.10" -T fields -e "dns.qry.name" -r kattastrofen.pcap > output.txt
```
Now we have all the data. Futher research of DNSCat tell that the there are bytes in the beginning of each string that gives instruction to a server. These instructions need to be taken out. When skimming over the data the first 18 characters are always similar each line. Also cutekittenzz.xyz domain name need to be filtered out and the extra dots. The python code below will clean up the file
```
file = open('output.txt', 'r')
newFile = open("newoutput.txt", "x")

with open("output.txt") as file:
    for line in file:
        slicedBeginning = line[18:]
        slicedEnding = slicedBeginning[:len(slicedBeginning)-17]
        removedDots = slicedEnding.replace(".", "")
        print(removedDots)
        newFile.write(removedDots)
```
![alt text](https://github.com/tg222eu/KattastrofenCTF/blob/main/pictures/xor.JPG)<br>

We now have a file in hex value. We can convert it "from hex" in cyberchef. The new text give us size: 378880, md5: 9d9b374c33a8672f8f8f1af871d7d04f and all the encrypted data.

We now have the encrypted data. By using cyberchef we can decrypt the data by using "from base64" and use the key found in the script in XOR. The MD5 matches

Downloading the file as tar, opening it up and we find it contains a PDF file. Opening the PDF file contain a picture of flag nr 2.

![alt text](https://github.com/tg222eu/KattastrofenCTF/blob/main/pictures/flag2.JPG)<br>

Flagga2{every_day_is_caturday}

## Flag 3

![alt text](https://github.com/tg222eu/KattastrofenCTF/blob/main/pictures/wordjavascript.JPG)<br>

Futher investigating the content inside the PDF file by opening a text editor, we find there is a javascript object with a lot of hex characters.

![alt text](https://github.com/tg222eu/KattastrofenCTF/blob/main/pictures/JSFuck.JPG)<br>

By converting the hex to UTF-8 we get a code with a lot of brackets, parentheses, plus signs and exclamation mark. A quick research reveals that this is JSFuck encrypted. I tried several different tools and the only one that worked was https://enkhee-osiris.github.io/Decoder-JSFuck/. Once decrypted we get a Javascript code. 

![alt text](https://github.com/tg222eu/KattastrofenCTF/blob/main/pictures/flagga3.JPG)<br>

Since 0.1 + 0.2 == 0.3 will result in tiny rounding errors, because of limitation in floating-point arithmetic in programming in general, the statement will always be false. I removed the if statement since its not fulfilling any purpose. I also removed the app.alert and replaced it with console.log just because of curiousity what the output would look like and it revealed the flag.

Flagga3{mj4u!}
