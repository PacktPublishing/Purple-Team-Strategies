


# Purple Team Strategies

<a href="https://www.packtpub.com/product/purple-team-strategies/9781801074292"><img src="https://static.packt-cdn.com/products/9781801074292/cover/smaller" alt="Book Name" height="256px" align="right"></a>

This is the code repository for [Purple Team Strategies](https://www.packtpub.com/product/purple-team-strategies/9781801074292), published by Packt.

**Enhancing global security posture through uniting red and blue teams with adversary emulation**

## What is this book about?
With small to large companies focusing on hardening their security systems, the term "purple team" has gained a lot of traction over the last couple of years. Purple teams represent a group of individuals responsible for securing an organization’s environment using both red team and blue team testing and integration – if you’re ready to join or advance their ranks, then this book is for you.

This book covers the following exciting features: 
* Learn and implement the generic purple teaming process
* Use cloud environments for assessment and automation
* Integrate cyber threat intelligence as a process
* Configure traps inside the network to detect attackers
* Improve red and blue team collaboration with existing and new tools
* Perform assessments of your existing security controls

If you feel this book is for you, get your [copy](https://www.amazon.com/Purple-Team-Strategies-Enhancing-adversary-ebook/dp/B0B12R8DFJ) today!

<a href="https://www.packtpub.com/?utm_source=github&utm_medium=banner&utm_campaign=GitHubBanner"><img src="https://raw.githubusercontent.com/PacktPublishing/GitHub/master/GitHub.png" alt="https://www.packtpub.com/" border="5" /></a>

## Instructions and Navigations
All of the code is organized into folders. For example, Chapter03.

The code will look like the following:
```
alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS
(
     msg: "Detecting HTTP URI with a malicious string as parameter"
     http_uri;
     content:"/malicious=";
     pcre:"/\/malicious\x3d\w+/";
)
```

**Following is what you need for this book:**
If you're a cybersecurity analyst, SOC engineer, security leader or strategist, or simply interested in learning about cyber attack and defense strategies, then this book is for you. Purple team members and chief information security officers (CISOs) looking at securing their organizations from adversaries will also benefit from this book. You’ll need some basic knowledge of Windows and Linux operating systems along with a fair understanding of networking concepts before you can jump in, while ethical hacking and penetration testing know-how will help you get the most out of this book.

With the following software and hardware list you can run all code files present in the book (Chapter 1-14).

### Software and Hardware List

| Chapter  | Software required                                                                                  | OS required                        |
| -------- | ---------------------------------------------------------------------------------------------------| -----------------------------------|
| 1-14     | Python, Ansible, Powershell									                                                      | Windows, Mac OS X, and Linux (Any) |


We also provide a PDF file that has color images of the screenshots/diagrams used in this book. [Click here to download it](https://static.packt-cdn.com/downloads/9781801074292_ColorImages.pdf).

### Related products <Other books you may enjoy>
* Mastering Defensive Security[[Packt]](https://www.packtpub.com/product/mastering-defensive-security/9781800208162) [[Amazon]](https://www.amazon.com/Mastering-Defensive-Security-techniques-infrastructure/dp/1800208162)

* Cryptography Algorithms [[Packt]](https://www.packtpub.com/product/cryptography-algorithms/9781789617139) [[Amazon]](https://www.amazon.com/Next-generation-Cryptography-Algorithms-Explained-implementation-ebook/dp/B093Y11H9Q)

## Get to Know the Authors
**David Routin**
He became interested in computer security at a young age. He started by learning about old-school attack methods and defense against them in the 1990s with Unix/Linux systems. He now has over two decades of experience and remains passionate about both sides of security (offensive and defensive). He has made multiple contributions to the security industry in different forms, from the MITRE ATT&CK framework, the SIGMA project, and vulnerability disclosures (Microsoft) to public event speaking and multiple publications, including articles in the French MISC magazine.
As a security professional, he has held multiple positions, including security engineer, open source expert, CISO, and now security operations center (SOC) and Purple Team manager at e-Xpert Solutions. Over the last 10 years, he has been in charge of building and operating multiple SOCs for MSSPs and private companies in various sectors (including industry, pharma, insurance, finance, and defense).

**Samuel Rossier**
He is currently SOC lead within a government entity where he focuses on detection engineering, incident response, automation, and cyber threat intelligence. He is also a teaching assistant at the SANS Institute. He was previously responsible for a private bank group CIRT, and also worked as an SOC manager within an MSSP. He also spent several years within a consulting cybersecurity practice.
Samuel currently holds a master's degree in information systems and several information security certifications, including GRID, GMON, eCIR, eCTHP, eCRE, eNDP, and eJPT.
He is also a contributor to the MITRE D3FEND and SIGMA frameworks and likes to speak at conferences and analyze malware. He values a strong emphasis on the people dimension of cybersecurity by sharing knowledge.

**Simon Thoores**
He is a cybersecurity analyst who specializes in forensics and incident response. He started his career as a security analyst after obtaining an engineering diploma in information system architecture with a focus on security. He built his forensics and reverse engineering skills during large-scale incident responses, and he finally validated these skills with GCFA. Then, he moved to the threat intelligence field to better understand and emulate attackers in order to improve infrastructure security.
### Download a free PDF

 <i>If you have already purchased a print or Kindle version of this book, you can get a DRM-free PDF version at no cost.<br>Simply click on the link to claim your free PDF.</i>
<p align="center"> <a href="https://packt.link/free-ebook/9781801074292">https://packt.link/free-ebook/9781801074292 </a> </p>