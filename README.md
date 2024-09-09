# CISA-ICS-CTF-2024

## CTF Overview

CISA’s annual Capture the Flag (CTF) is oriented around an incident response scenario involving attacks on critical infrastructure. This year, the featured critical infrastructure sectors are city infrastructure, water purification, medical facilities, and railway.
In this Capture the Flag event, you will be serving the role as an incident responder investigating various cyber incidents that occurred in the small city of Driftveil. This CTF is split into five main categories: Security Foundations, Driftveil City, Castelia Solutions, Virbank Medical, and Anville Railway.

## Objective

Being that this was my first CTF, the objective was simple: learn as much as possible. I wanted to expose myself to things I may not have came across in my near future and to test my determination and analytical skills. My teammate and I placed **96th** out of **1193** teams.

### Skills Learned

- Correlating data between a database and poorly implemented data within Malcolm
- Developed navigational and analytical skills within Malcolm
- Developed navigational and analytical skills within Netbox
- Analysis of KAPE capture data to find unexpected network traffic
- Reverse engineering code to understand how the executable works and to find what and where information was sent
- Elevated documentation comprehension
- Better understanding of traffic/communications within Wireshark
- Decryption of data to discover vital information
- Digital Forensics
- Static and Dynamic Code Analysis
- Overall heightened analytical skills to uncover subjectively difficult answers

### Tools Used

- Malcolm - a powerful network traffic analysis tool suite this is easy to deploy and configure. It provides full packet capture artifacts (PCAP files), Zeek logs, and     Suricata alerts as well as dashboard interfaces to display and analyze collected information
- Netbox - an open-source tool that helps network engineers model and document a network's infrastructure
- KAPE - a tool that helps forensic investigators collect and process forensically useful artifacts from a device or storage location
- Wireshark -  open-source network protocol analyzer that captures and displays network traffic in real time
- CyberChef - open-source web app that allows users to perform a variety of data manipulation tasks, such as encoding, decoding, and encryption

## Steps

### Security Foundations

- The start of the CISA CTF began with an introduction to the various tools and techniques used within this CTF. This included manipulation of inspect, changing cookies, using CyberChef, an introduction to Malcolm etc.
  
  ![securityfoundations](https://github.com/user-attachments/assets/b537731e-0eaa-4973-8224-49225d0d259f)

### Driftveil City

- Driftveil City is a small city on the coast and has been experiencing issues with their city infrastructure ICS protocols

#### Register the Dots - 1

  ![Discord_aWc5EleEXW](https://github.com/user-attachments/assets/f4e3f151-06a6-4edc-977f-903aff727c99)

- Downloaded the KapeCap file, which was a duplicate image of Benji’s computer
- Looked through the event viewer and checked network profiles, security, applications, and systems. Filtered for various event IDs. Nothing corresponded to unexpected network connections
- On Linux, ran a Find command:
  
  ```bash
  find ./ -iname *pcap*
  find ./ -iname *.pf*
  ```

- 2 .pf files were found, however, they were not of use. The next command:
  
  ```bash
  find ./ -iname *.exe*
  ```

  ![Discord_sSmXrMzVyh](https://github.com/user-attachments/assets/e44ddc11-855e-4944-badd-8571a7222488)

- The find command on .exe showed various files within the recycle bin and 2 files in the temporary folder
- Generated a hash with md5sum for each file and found ditto.exe to be suspicious
- Upon further investigation, it was noticed that ditto.exe was masquerading as ditto.dll which is a program used by windows notepad

  ![Discord_BHU7UQNrmM](https://github.com/user-attachments/assets/09b291c6-4480-42a5-913c-363b8dcd4a2a)

- Since ditto.exe was in the roaming/tmp folder, the assumption was made that it could be the process that was run during startup and ultimately was the flag

 #### Register the Dots - 2A

 ![chrome_QCGEpf3bg1](https://github.com/user-attachments/assets/def3abf2-504c-4ba0-9a07-79d1edd06b67)

- After discovering ditto.exe, a controlled windows environment was created to execute the program with Wireshark running to capture the traffic
- Ditto.exe was then inputted into VirusTotal, which discovered connections made, and code pointing towards the IP address 165.227.251.182, an HTTP request, Base64 encoding, and malicious activity

  https://www.virustotal.com/gui/file/61b60fd559bc4fdb6342aa83ec9354948c98036bb30a26173e3c18b19a184d98/details
  
- To cross reference the information from VirusTotal, a static analysis was ran on ditto.exe
- Sifted through the file’s code on Notepad and searched for keywords such as IP and password, and found an environment variable and its Base64 encoding 

  ![chrome_wrIwwHAewY](https://github.com/user-attachments/assets/3ee653dc-9a06-4830-a08a-16ff38272444)

- The code pointed to a file /FileZilla/sitemanager.xml
- ran a find command on the .xml file:
  
  ```bash
  find ./ -iname *.xml*
  ```

  ![Discord_QMIWrcKMYE](https://github.com/user-attachments/assets/8118fad2-c5f4-48a8-8bc3-73fa3437c009)

- After discovering the path, a cat command was ran to discover what was in the file

  ```bash
  cat ./C/Users/Benji/AppData/Roaming/FileZilla/sitemanager.xml
  ```

  ![Discord_efAZkGF7He](https://github.com/user-attachments/assets/22ce4b1b-5be1-492a-b87e-f3ae2ecab996)

- Noticed an IP address as well as a password that was encoded with base64
- Used CyberChef with the recipe "From Base64 and received: easy2W3ar which ended up being the flag

#### Register the Dots - 2B

  ![Discord_Wy6ogx9kjG](https://github.com/user-attachments/assets/2ac1a2a2-df14-4964-a491-7b20c825e16c)

- The previous investigation uncovered both 2A and 2B

#### Learning To DRIFT - 1

The following is information from the PDF:

  ![Discord_A2wre9xbcb](https://github.com/user-attachments/assets/d20d1414-e51f-4424-8234-bb4cb7f5671d)

  ![Discord_lFjVxZYcZp](https://github.com/user-attachments/assets/dd653393-9b36-4f7c-86df-d79b2425754e) ![Discord_m4tCGa34kP](https://github.com/user-attachments/assets/dca33b49-0b61-4d23-956e-4f7b124af50b)![Discord_VqgDiqgeot](https://github.com/user-attachments/assets/64319c33-5d62-4e47-9022-8ba8b607bf99)

- Looked for a 3-byte payload, which would be the start of a communication thread and a NEW-CONNECTION-REQUEST:

  ![Discord_4Z7sQesVZS](https://github.com/user-attachments/assets/17e7f5b6-22af-41e4-8c72-d90419d8c8a9)

- The next communication in the TCP Stream is a 12-byte payload, which should be a NEW-CONNECTION-RESPONSE. In the response, the partial key should be the last 8 bytes of the payload:

  ![Discord_GlfzTf4xNJ](https://github.com/user-attachments/assets/e065140d-d0f1-4bce-875e-f109b4e73eaf)

- Partial key: 61 cb 50 6b 8f f1 b4 77
- The next communication in the TCP Stream is a 26-byte payload, and it should include the second half of the partial key:

  ![Discord_efQI3gJ3jr](https://github.com/user-attachments/assets/e31482b9-8298-45a3-a3f2-89ef69901a0f)

- Partial Key: a9 de 4b 26 a7 1f 69 89 
- Full Key: 61 cb 50 6b 8f f1 b4 77 a9 de 4b 26 a7 1f 69 89
- Copied the 26-byte payload from Wireshark, excluding the first 10 bytes (the first 2 bytes are data length, and the next 8 are the partial key), and added it to the input
- Used 'AES decrypt' with an ECB mode as the recipe:

  ![chrome_kUIiXXTpU9](https://github.com/user-attachments/assets/8f630cfa-1f01-4278-bd7f-1f275bfbb1ff)

- The question specifies ‘integer,’ so the conversion from hex to decimal is as follows:
  03 = 3
  64 = 100

- 03 message code signifies a READ-SENSOR, and sensor ID 100 corresponds to the question
- The next communication in the TCP Stream should be the READ-SENSOR-RESPONSE:

  ![chrome_86Cg0uQACo](https://github.com/user-attachments/assets/bee54ba1-0cd5-434f-b51b-cf08a69926df)

- Partial key: 91 91 c4 5d 7f e2 dd ca
- The new full key uses the initial partial key from the original 12 byte payload + the new 8 bytes from the current communication
- Full Key: 61 cb 50 6b 8f f1 b4 77 91 91 c4 5d 7f e2 dd ca
- Added the payload into CyberChef excluding the first 10 bytes:

  ![chrome_5HNrXn8SYt](https://github.com/user-attachments/assets/b8b012de-f3a8-40fe-8bac-cad4bf8fbb6b)

- The output: 03006400000206
- The data structure for a READ-SENSOR-RESPONSE contains a message code (1 byte), response code (1 byte), sensor (1 byte), and value (4 bytes)
- message code: 03 
  Sensor ID: 64 (100 in decimal)
  Value: 0x206 (518 in decimal)

 ![Discord_7XppAxqWHt](https://github.com/user-attachments/assets/0c2dda2a-5a59-4ecb-a6d1-33c25c90b666)

#### Learning To DRIFT - 2
  
  ![chrome_aOuTP93wK5](https://github.com/user-attachments/assets/a1694d7f-a648-4cb7-9570-2799481964aa)

- Looked for a 12-byte payload, which is a new connection response that holds the partial AES key: 

  ![chrome_zIa6J9ENjK](https://github.com/user-attachments/assets/257e0b7a-cafc-4759-b8aa-0e3432f39174)

- Partial Key: 9b c6 65 88 0b 5d f8 fc
- The next communication in the TCP stream with the partial AES key:

  ![chrome_Toj5XS59BJ](https://github.com/user-attachments/assets/18596d95-815a-4f8a-acea-cda52c293f27)

- Partial Key: 8d de c2 02 7f 01 72 a4
- Full Key: 9b c6 65 88 0b 5d f8 fc 8d de c2 02 7f 01 72 a4
- Used the key and AES ECB decryption

  ![chrome_En1lCqsP7y](https://github.com/user-attachments/assets/c7874a70-86e2-406d-ae0f-f10fb43264db)

- Output 07 in decimal is 07, which signifies a GET-ALARM-REQUEST:

  ![chrome_NcI1BS5eXp](https://github.com/user-attachments/assets/9a0f45e0-52bd-440c-898c-7abae9e73005)

- The next communication should be a GET-ALARM-RESPONSE:

  ![chrome_yDiDNafzlQ](https://github.com/user-attachments/assets/8dccc682-dfdd-4b02-a8b7-6aed75448a11)

- Using the initial partial key: 9b c6 65 88 0b 5d f8 fc
- With the new partial key: 64 31 4c b8 4d 00 ad de

  ![chrome_F0u8JLagM0](https://github.com/user-attachments/assets/3b1699c3-1f1a-46b5-b9be-a6c5ab628153)

- Output: 07000266a00000003f6bb10000041a
- Looking at the data structure of a GET-ALARM-RESPONSE:

  ![chrome_8yfzOpJdSk](https://github.com/user-attachments/assets/afffc069-e059-4fe7-8f7c-66d47d210a10)

- Disregarding data length and partial key, we have:
  - Message code(GET-ALARMS) - 1 byte
  - Response code(Success) - 1 byte
  - Alarm count - 1 byte
  - List of ALARM-DATA - 6 * Alarm count
    
  - ALARM-DATA has an additional data structure:

    ![chrome_QrC9aa3BcX](https://github.com/user-attachments/assets/156aab18-f933-4745-94aa-28ab8d4ffb97)

  - The bytes are multiplied by the alarm count
  - If we break down the output: 07 00 02 66 a0 00 00 00 3f 6b b1 00 00 04 1a, we get:
  - Message code: 07
  - Response code: 00
  - Alarm count: 02
  - We should be left with 12 bytes: 66 a0 00 00 00 3f 6b b1 00 00 04 1a
 
  - Each alarm count is 6 bytes of data:

  - Alarm 1: 66 a0 00 00 00 3f
  - Alarm 2: 6b b1 00 00 04 1a
  - Since the data structure for ALARM-DATA is as follows:
  - Sensor ID: 1 byte
  - Alarm code: 1 byte
  - Value: 4 bytes
  - Alarm Codes:

    ![chrome_gLiC353jW3](https://github.com/user-attachments/assets/97b1324e-49ec-4025-a8a9-efc782cd48c6)

  - Translated into decimals:
  - Alarm 1: 66(102), a0(WARNING:LOW), 0000003f(63)
  - Alarm 2: 6b(107), b1(ALERT:HIGH), 0000041a(1050)
  - The question asked: What is the sensor value of the sensor that is reporting an ALERT-HIGH alarm code?

    ![chrome_XUW40GIqAZ](https://github.com/user-attachments/assets/7962ce7d-37e1-41ab-a264-1e153b4ef977)


#### Learning To DRIFT - 3

![Discord_bMUK6f2UsJ](https://github.com/user-attachments/assets/7adf240e-a19c-4734-998c-4d0c87fe53ee)

- Looked for a 12-byte payload, which is a new connection response that holds the partial AES key:

  ![chrome_89Nv3MxR9f](https://github.com/user-attachments/assets/ef6183ff-0a98-486a-ac7d-2b9016545a26)

- Partial Key: 85 dc 31 1f eb 51 03 33
- In the TCP stream, the next communication is a 26-byte payload. We are currently looking for a GET-SENSOR-RANGES:

  ![chrome_ZUCcwPYsYw](https://github.com/user-attachments/assets/7756f1b0-a86c-4a0c-9207-cb91ebb917c0)

- Partial Key: 3c 06 93 43 b5 ed ed 4d
- Full Key: 85 dc 31 1f eb 51 03 33 3c 06 93 43 b5 ed ed 4d
- Decrypting the 26-byte payload:

  ![chrome_WuxutvtFtI](https://github.com/user-attachments/assets/05c6f9ec-8263-4b46-ad87-0a714b2282b0)

- Data Structures:

  ![chrome_FzacSV6dlW](https://github.com/user-attachments/assets/358873ee-dcc9-49ee-8410-aeb7f54a32ad)![chrome_wD6YwNbCh2](https://github.com/user-attachments/assets/91797d64-24fd-47ac-8b1d-bfaa2df3be21)

- Output: 036c
  - 03 is a Read Sensor
  - 6c is Sensor ID 108
- The next communication in the TCP stream is:
  
  ![chrome_iAW6yvXhmc](https://github.com/user-attachments/assets/a786de7d-11f0-4985-bd3e-64215b634ed5)

- Partial Key: 96 96 e1 bb f2 65 7f 37
- New Full Key: 85 dc 31 1f eb 51 03 33 96 96 e1 bb f2 65 7f 37
  
  ![chrome_wpi8ldgfZH](https://github.com/user-attachments/assets/651a403c-577a-496c-b581-62be7bfcc25d)

- Output: 0303
  - 03 is a read sensor; however, the next communication should have been a READ-SENSOR-RESPONSE. Given the output was 0303, signifying a READ-SENSOR, the next 03 is an error
    
    ![chrome_mcwzdIXJ9W](https://github.com/user-attachments/assets/f0811bd5-cf8d-4481-b9e5-f96a6dcbad4c)
    
  - An 03 error is: ERROR: Sensor not found:

    ![chrome_rd7BewTWNC](https://github.com/user-attachments/assets/3138aa85-925c-4668-bd25-7d6467ed0e18)

- Next communication in the TCP Stream:

    ![chrome_cn9r2rqxUg](https://github.com/user-attachments/assets/5ad49115-cb29-4808-9d0d-1b5cfce34876)

- Partial Key: 6c a3 71 51 eb cb 15 1f
- Full Key: 85 dc 31 1f eb 51 03 33 6c a3 71 51 eb cb 15 1f

  ![chrome_qOXs6hBckx](https://github.com/user-attachments/assets/30a9aa1b-27ce-4316-98fe-6d3ba7d75293)

- Output: 06086a6b6d6e6f707172
- The message code 06 signifies a GET-SENSOR-RANGES

  ![chrome_QIok35FksX](https://github.com/user-attachments/assets/c4a8938d-dbd5-4afe-ac8d-99062fbb6a0c)

- Breaking down the output 06086a6b6d6e6f707172:
  - A GET-SENSOR-RANGES-REQUEST:

    ![chrome_hU0KchxHIF](https://github.com/user-attachments/assets/6652af2d-c4fe-49f4-8395-783eee44fbfa)

  - Message Code: 06
  - Sensor count: 08
- We are left with: 6a 6b 6d 6e 6f 70 71 72
  - Sensor 1: 6a (106)
  - Sensor 2: 6b (107)
  - Sensor 3: 6d (109)
  - Sensor 4: 6e (110)
  - Sensor 5: 6f (111)
  - Sensor 6: 70 (112)
  - Sensor 7: 71 (113)
  - Sensor 8: 72 (114)
- The following communication in the TCP Stream should be a GET-SENSOR-RANGES-RESPONSE:

  ![chrome_HNv91dLk1w](https://github.com/user-attachments/assets/100fda6d-c4cc-4f25-81ce-fc380c8604b5)

- Partial Key: 65 2a 84 85 fa 19 e7 36
- Full Key: 85 dc 31 1f eb 51 03 33 65 2a 84 85 fa 19 e7 36
- Decrypting the 154-byte payload:

  ![chrome_jZgKfpeMgb](https://github.com/user-attachments/assets/34b2d04d-70d6-424c-84db-0326f9e6580e)

- The output is a GET-SENSOR-RANGES (RESPONSE):
  0600086a000000020000000600000001000000076b0000032000000384000002bc000003e86d0000032000000384000002bc000003e86e0000002300000028000000210000002a6
  f0000000f000000190000000c0000001c700000000f000000190000000c0000001c710000271000002af80000232800002ee07200000001000000030000000000000004

- A response includes:

  ![chrome_nFb8PUswJ8](https://github.com/user-attachments/assets/edd50a00-42c8-4e94-89d7-58d76771382a)

- SENSOR-RANGES has an additional data structure:

  ![chrome_I5jw8X3Cit](https://github.com/user-attachments/assets/5fa0a1af-ffc7-4267-b28d-0b3b616ae79c)

  - Message code: 06
  - Response code: 00
  - Sensor count: 08
  - Sensor 1: 6a 00 00 00 02 00 00 00 06 00 00 00 01 00 00 00 07 
  - Sensor 2: 6b 00 00 03 20 00 00 03 84 00 00 02 bc 00 00 03 e8 
  - Sensor 3: 6d 00 00 03 20 00 00 03 84 00 00 02 bc 00 00 03 e8 
  - Sensor 4: 6e 00 00 00 23 00 00 00 28 00 00 00 21 00 00 00 2a 
  - Sensor 5: 6f 00 00 00 0f 00 00 00 19 00 00 00 0c 00 00 00 1c 
  - Sensor 6: 70 00 00 00 0f 00 00 00 19 00 00 00 0c 00 00 00 1c 
  - Sensor 7: 71 00 00 27 10 00 00 2a f8 00 00 23 28 00 00 2e e0 
  - Sensor 8: 72 00 00 00 01 00 00 00 03 00 00 00 00 00 00 00 04

  ![chrome_37aZNUjM6g](https://github.com/user-attachments/assets/e388c1d1-df05-42e5-bfc4-af11f1c4a3b2)

- We have the ranges; now we look for the next communication:

  ![chrome_NzTUIEB9N6](https://github.com/user-attachments/assets/479217c0-4e5e-42af-8b15-63821f809d70)

- Partial Key: 9b c6 65 88 0b 5d f8 fc
- The next communication in the TCP stream:

  ![chrome_uXhxACElsw](https://github.com/user-attachments/assets/0df3e272-0b08-4543-bf55-c18d19ca62f3)

- Partial Key: 8d de c2 02 7f 01 72 a4
- Full Key: 9b c6 65 88 0b 5d f8 fc 8d de c2 02 7f 01 72 a4
- Output:

 ![chrome_AEFPPK1zFO](https://github.com/user-attachments/assets/7fb73e59-e5f2-4ad8-a12b-1e01c4fd7ad4)

- 07 signifies a GET-ALARMS request
- GET-ALARMS-RESPONSE:

  ![chrome_r5O8OvrQl6](https://github.com/user-attachments/assets/2a610840-9ae0-48a2-93f5-8e0e6c4b8d64)

- Partial Key: 64 31 4c b8 4d 00 ad de
- Full Key: 9b c6 65 88 0b 5d f8 fc 64 31 4c b8 4d 00 ad de

  ![chrome_JO473pYxMn](https://github.com/user-attachments/assets/339edadc-9009-44ee-8553-f2983456d145)

- Output: 07000266a00000003f6bb10000041a
- The GET-ALARMS-RESPONSE has the following data structure: 

  ![chrome_yewMlDXKCN](https://github.com/user-attachments/assets/e2adb26b-6070-4b6c-97a1-d31ee38c8aa4)

- Breakdown:
  - Message code: 07
  - Response code: 00
  - Alarm count: 02

- Alarm 1: 
  - Sensor: 66 (102) 
  - Alarm code: a0 (WARNING:LOW)
  - Value: 00 00 00 3f (63)

- Alarm 2: 
  - Sensor: 6b (107) 
  - Alarm code: b1 (Alert:High)
  - Value: 00 00 04 1a (1050)

- The next communication in the TCP Stream is:

  ![chrome_Y8KU72PB6o](https://github.com/user-attachments/assets/2cd08fb4-e78b-4b9b-94b6-6529379ef969)

- Partial Key: 64 c1 83 1b 8d 6b e4 0d
- Full Key: 9b c6 65 88 0b 5d f8 fc 64 c1 83 1b 8d 6b e4 0d

  ![chrome_w6ePhWUhtK](https://github.com/user-attachments/assets/4343d9e2-6fd3-4d2d-8003-4284fd84f404)

- 04 signifies a READ-ALL-SENSORS request
- READ-ALL-SENSORS-RESPONSE:

  ![chrome_ZorJCsrJPh](https://github.com/user-attachments/assets/5b223e43-6713-4423-a7cb-4faf27216a78)

- Partial Key: 1e f4 7c 31 5f 6a 40 17
- Full Key: 9b c6 65 88 0b 5d f8 fc 1e f4 7c 31 5f 6a 40 17

  ![chrome_eNRZ12HpUc](https://github.com/user-attachments/assets/edfad6d8-b4cf-4bf8-9716-333ca46a6327)

- Output: Output: 04000e7200000002700000001365000001bd640000020669000000466d0000033e71000027426a000000046f000000126e0000001f660000003f680000004867000000436b0000041a
- The READ-ALL-SENSORS-RESPONSE has the following data structure:

  ![chrome_MkWO6R1TpR](https://github.com/user-attachments/assets/8f1fe6c1-f33d-4ce4-99f5-edb9e79f45c1)

- Breakdown:
  - Message code: 04
  - Response code: 00
  - Sensor count: 0e (14)

- Sensor ID and Value in table format:

  ![chrome_dmMOSeZfaS](https://github.com/user-attachments/assets/0e0bbaad-a322-4a22-92d0-1beb18c21373)

- Integrated values with ranges in table format to determine which sensor is not reporting a GET-ALARMS:

  ![chrome_UYlkA1h7x8](https://github.com/user-attachments/assets/56f09448-ef55-4dac-8f10-8fac2ce9d8e2)


- Sensor 107 and 110 are out of range; however, in our ‘GET-ALARMS-RESPONSE,’ sensor 107 provided an alert, whereas 110 did not

  ![Discord_I72Bd1xbNk](https://github.com/user-attachments/assets/2b7b2b50-0f9e-4fe5-8827-a5913c8c9230)
  

### Castelia Solutions

- Castelia Solutions is the primary water-treatment facility for Driftveil and have been experiencing issues with their Historian and various embedded devices

#### MODifying History 1

  ![chrome_uQhVTR1pgN](https://github.com/user-attachments/assets/61a9f7bc-ba3b-45e0-b94a-3b595608f67f)

- In Malcolm, looked at the detailed Modbus logs and filtered 'zeek.modbus_detailed.values' = 31 which was found in the castelia_historian.db

  ![chrome_9xXtnGAUVL](https://github.com/user-attachments/assets/066dadc9-21b1-433f-b9c8-bd9892e3c83c)

- To access all corresponding data, 'surrounding documents' was clicked. Compared the timestamp and value to the the data and found 27 as the input register:

  ![chrome_rHd5rjN4NC](https://github.com/user-attachments/assets/d869b228-bb3a-4ae2-a11c-7ec6724ef1a4)

  ![chrome_1BwGAYzqdg](https://github.com/user-attachments/assets/eb0a6f96-f07f-4255-9898-9b2257c5037b)


### Virbank Medical

- Virbank Medical is the main hospital serving Driftveil and its surrounding towns and has been experiencing issues due to ransomware and poor cyber hygiene

#### Extend Your Stay - 1

  ![chrome_jKX3SQvv7i](https://github.com/user-attachments/assets/a159bcaf-2914-4fb2-8171-b2a0838af111)

- Downloaded the 'no_more_rodents.crx', unzipped the file into a folder named extension:

  ![chrome_KSVYJNxF7i](https://github.com/user-attachments/assets/acb18c56-e919-49e3-81d6-35714bd59012)

- Opened Google through the CLI attempting to load the extension. The extension failed to load, so we manually loaded it the load unpacked option:

  ![chrome_euOnZue9Dw](https://github.com/user-attachments/assets/cdf810f1-f811-480e-8ca1-2f15e366a72d)

- Once the extension loaded, selected the 'service worker' inspect view to retrieve the flag:

  ![chrome_3DRCmcy6sv](https://github.com/user-attachments/assets/7a0e6475-f33b-4560-8be4-8897c42c3e62)

  ![chrome_Cxs0af5MsH](https://github.com/user-attachments/assets/6233a5f8-1c97-40d2-86a8-b9dd1a90d787)

  ![Photos_Li1dGCcpkW](https://github.com/user-attachments/assets/f1fe863c-0b37-47da-ba9b-4c96afbcdbb0)


#### Extend Your Stay - 2

  ![chrome_bmgOv2kSzO](https://github.com/user-attachments/assets/e086663c-2501-4da7-b7e3-bb48652a0a49)

- In JavaScript source code:
  
  ```javascript
  (atob('aHR0cHM6Ly93d3cud2VsbHNmYXJnby5jb20v'))&&(rodents[i][_0x4808c5(0xc1)]=atob('aHR0cHM6Ly93d3cuZmVsbHN3YXJnby5jb20v'));}
  ```
- The code uses Base64 encoding to obfuscate URLs. Leveraged ChatGPT to decode:

  ![chrome_p6lt7TfLM0](https://github.com/user-attachments/assets/ee7f6d1f-8cef-48a1-b3af-1f2ee932fea6)

#### Follow the Charts - 1

  ![chrome_PlqO37aMxf](https://github.com/user-attachments/assets/69f5f980-ed2a-45d4-a7d9-40599d6dd4d2)

- Downloaded the ZIP files
- Listed the downloaded files and then ran md5sum:

  ![Discord_BbpXZLNVzo](https://github.com/user-attachments/assets/415bc5f2-8df6-4375-b4f6-d57d1c819912)

#### Follow the Charts - 2

  ![chrome_sHHodzlfH7](https://github.com/user-attachments/assets/c124e1e7-0698-4c98-8a4f-5b1c63daf5a8)

- The .lib file was an executable, and the permissions showed that it was only read/write
- Changed the permissions with chmod

  ![chrome_UAlCAvnHf9](https://github.com/user-attachments/assets/ad47fa60-f90d-4ba2-9708-f18f8197d9f5)

- Once permissions were changed, in a controlled environment, the program was executed to obtain the flag.txt and complete the question:

  ![Discord_R5qgNqfuY0](https://github.com/user-attachments/assets/73c9ebad-e68f-429a-8638-15470eb17dc9)

#### Mission: Inconceivable - 1

  ![chrome_S1njyYp4O5](https://github.com/user-attachments/assets/7c521168-6256-4a58-a822-5b4144846cbf)

- Analyzed the .jpg

  ![Discord_MMXLJeDxuo](https://github.com/user-attachments/assets/3270729c-0a31-4089-a40a-e3c81442ad7f)

- Noticed the barcode in the bottom right side of the image and rotated it for a better view:

  ![Discord_Gr2k9S77pe](https://github.com/user-attachments/assets/f57d0de9-cb80-4543-8356-0f0552e0fa44)

- Used a 3rd party website to decode the barcode:

  ![chrome_qOrf9cGNY9](https://github.com/user-attachments/assets/23da6d8a-f32b-447c-97de-44af33fc9994)

- Looked up the ZIP Code:

  ![chrome_55PZTa9IMz](https://github.com/user-attachments/assets/5dddc39d-5e4b-4672-9804-8551a1bea40a)

  ![chrome_fW0R3xCwNR](https://github.com/user-attachments/assets/d0fde19f-435a-461e-b3b2-87ca11335dd3)

#### Mission: Inconceivable - 2

  ![chrome_KKJ5YxKfJp](https://github.com/user-attachments/assets/969f6955-bc97-4379-8939-b5e796897385)

- Control F 'taco'

  ![chrome_JFPVGJii6S](https://github.com/user-attachments/assets/0b933bf1-cfd1-4893-9b2e-48ca9cde66b6)

- Used the MAC address:

  ![Discord_pWqNPe3FH5](https://github.com/user-attachments/assets/ed9be35a-0854-419c-84ca-c2ca9e787db5)


### Anville Railway

- Anville Railway is a large rail-transport operating company headquartered in Driftveil and has been experiencing issues with their ICS network and devices

#### Genisys of the Problems - 1

  ![chrome_WlncRQKt6i](https://github.com/user-attachments/assets/cff12771-e2fa-4b88-8b62-1f1c741e2cee)

- In Malcolm, filtered zeek.genisys.server = exists:

  ![Discord_S1QRFq9XoR](https://github.com/user-attachments/assets/30d896e6-863b-49e3-8ca3-e5cb5252e1aa)

- Noticed one "execute controls" with no results:

  ![Discord_Ixd0sa0Glx](https://github.com/user-attachments/assets/8823d391-2718-4615-a570-5be5eb6f036e)

- Added it to filters:

  ![chrome_ekHlqnPPMT](https://github.com/user-attachments/assets/79951d8f-071d-4493-9107-0b287576eb7d)

  ![Discord_lNIIycYXv4](https://github.com/user-attachments/assets/2f9adc1b-d25d-4ba6-8171-f23fd9213eb2)

#### Genisys of the Problems - 2

  ![chrome_4asGdi25xr](https://github.com/user-attachments/assets/aff12352-3ee5-4db4-8dd9-ce907e98a7dc)

- Filtered calculated and transmitted values, and looked for the mismatched values:

  ![chrome_mt61x3uhqq](https://github.com/user-attachments/assets/545927c8-e402-429d-9b11-e2ff4783f043)

#### Genisys of the Problems - 3

  ![chrome_spdbQuQD0g](https://github.com/user-attachments/assets/c7bc81a1-62ae-49ac-ba99-98a72708cadd)

- Looking at the previous mismatched CRC, opened the log to find the highest Data address:

  ![Discord_c9tSrAzx7A](https://github.com/user-attachments/assets/c8e1ded8-db95-4ab2-a4c0-627849a96058)
  
#### Modeling Trains - 1

  ![chrome_WZxK9gB3xS](https://github.com/user-attachments/assets/848309af-6778-4459-a0b8-6e0d5d78a89c)

- Went to netbox and searched for Station 8 Historian and found the IP:

  ![Discord_A1RPntqi0m](https://github.com/user-attachments/assets/828f9251-99cd-4b2a-a055-0f74ae690d5d)

#### Modeling Trains - 2

  ![chrome_vfCwlM9fpu](https://github.com/user-attachments/assets/23e3a78f-9199-40aa-ad44-425ebd3513ec)

- Searched: Station 9, clicked on station 9:

  ![Discord_zIqmYizXPS](https://github.com/user-attachments/assets/2e15a43f-d925-4008-bb42-1517085f5807)

- Counted all PLCs:

  ![Discord_uOkS84Ys9M](https://github.com/user-attachments/assets/3778e8a6-56b2-4f07-ad67-d8f526e4f7b7)

#### Modeling Trains - 3

  ![chrome_VaiaZ4dwfv](https://github.com/user-attachments/assets/340f6550-c635-4b84-8e86-04a3cd458bc8)

- Sifted through the information to find a duplicate IP address for station 13 and 14:

  ![Discord_9WgrpIWE04](https://github.com/user-attachments/assets/1b61cef8-f959-42ac-8412-513f7e11c49d)

- After clicking on the IP it also showed for station 14:

  ![Discord_SQeB14LmVn](https://github.com/user-attachments/assets/335cd0ae-663d-4e08-8466-85ae74fbd1b8)

- Station 14:

  ![Discord_02VvVs6bqz](https://github.com/user-attachments/assets/3dd35d16-cd8f-464d-b6b3-45006a8e4d18)

- Workstation:

  ![Discord_aziAbxpXt0](https://github.com/user-attachments/assets/9a498bcc-95c3-4545-9a78-f065eba0d7fc)


## Conclusion

Participating in my first CTF was a rewarding and eye-opening experience. I went in unsure of what to expect, but my primary goal was to learn—and I certainly did. This CTF pushed me to think critically in ways I didn’t even know I could. More than just finding the answers, I wanted to understand everything I was doing, and I made sure of it. Throughout the process, I gained hands-on experience with a variety of tools, learned how to decode and decrypt data, reverse engineer code, connect documentation with data, and collaborate with a teammate.

It's funny how something can seem so complex at first, but once understood, it becomes remarkably simple. I never once felt discouraged; each challenge only strengthened my resolve to find the solution. I'm truly eager to apply this newfound knowledge in future CTFs and my cybersecurity career.
