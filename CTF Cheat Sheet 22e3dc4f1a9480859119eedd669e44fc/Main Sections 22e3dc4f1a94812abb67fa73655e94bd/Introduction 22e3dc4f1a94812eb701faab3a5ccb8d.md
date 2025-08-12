# Introduction

# **🚩Home - Practical CTF**

**Overview:**
A big collection of my notes for Capture The Flag (CTF) challenges or Hacking in general

📋  Contains lots of copy-paste-ready commands/scripts to get things done quickly

🧠  I aim to explain as much as possible how and why the attack works

👨‍💻  Inspired by [HackTricks](https://book.hacktricks.xyz/welcome/readme) but in my style, and including all the experiences I've had

**Tips & Strategies:**

### 1. **Know the Patterns**

CTF challenges often repeat similar structures. Familiarize yourself with the types of problems common in your category (e.g., Web, Crypto, Pwn). Think of it like math—if you know the formula, you can solve the equation faster.

### 2. **Solve with Speed and Understanding**

Don't just aim to solve challenges—aim to solve them *quickly* and *confidently*. Efficiency comes from recognizing patterns and practicing until the process becomes second nature.

### 3. **Use Writeups Wisely**

If you're stuck for more than 5 minutes, check a writeup. See how others solved the problem, then *redo it yourself* using what you've learned. This helps reinforce both the concept and the workflow.

### 4. **Don't Depend on Writeups**

Writeups are great learning tools, but don’t rely on them. In real competitions, you’ll face challenges with little to no documentation. Build your foundation so you’re ready for unfamiliar problems.

### 5. **Memorization is a Tool, Not the Goal**

Remembering techniques and scripts is useful—but true skill comes from understanding *why* a solution works. Combine memorization with deep comprehension to become a stronger player.

---

## **Common Question Types in CTF (Capture the Flag)**

---

### **1. What does a CTF challenge usually ask for?**

- **Format:**
    
    A flag is a specific string (usually wrapped like `flag{example}`) that you must find by exploiting or analyzing a challenge.
    
- **Example:**
    
    You exploit a vulnerable login page and receive this message:
    
    ```
    Welcome back admin! Here is your flag: flag{admin_access_granted}
    ```
    
- **Tip:**
Always know the flag format. Most CTFs use `flag{}` or similar. You can try submitting test flags early on to confirm the expected format.

---

### **2. What categories of challenges should I expect?**

- **Format:**
    
    Challenges are grouped by category, each testing a specific skill or concept.
    
- **Example:**
    - **Web** – SQL injection, XSS
    - **Crypto** – RSA, XOR, cipher puzzles
    - **Pwn** – Buffer overflows, memory corruption
    - **OSINT** – Internet sleuthing
    - **Forensics** – File or traffic analysis
    - **Reversing** – Binary or code dissection
- **Tip:**
    
    Pick one or two categories to focus on as a beginner. Master their typical challenges and tools before branching out.
    

---

### **3. How are CTF challenges typically structured?**

- **Format:**
    
    Each challenge usually has a title, a short description (sometimes with hints), a file or link, and a point value.
    
- **Example:**
    
    **Title:**
    
    "Secret Server"
    
    **Description:**
    
    "Can you find the admin password?"
    
    **Attachment:**
    
    ```
    server.py
    ```
    
    **Points:**
    
    100
    
- **Tip:**
    
    Read the title and description carefully—they often contain hidden clues or puns hinting at the exploit method.
    

---

### **4. How do I know what tool to use?**

- **Format:**
    
    The type of challenge and file format usually indicates the tools you’ll need.
    
- **Example:**
    - File looks weird? Try `binwalk`, `strings`, or `foremost`.
    - Network data? Use `Wireshark`.
    - Web challenge? Check source code, use Burp Suite or curl.
    - Encryption or hashes? Use `CyberChef`, `hashcat`, or write a script.
        
        Learn the category's typical tools and try them systematically.
        
- **Tip:**
    
    Build a personal cheatsheet of tools per category or use the websites. Over time, you’ll recognize patterns and know what to try first.
    

---

### **5. What should I do if I get stuck?**

- **Format:**
    
    If you're stuck for 5–15 minutes, look for hints in the challenge or consult a writeup. Then try solving it again yourself. 
    
- **Example:**
    
    You try to decode an encrypted string but fail. You find a similar writeup where someone used a Caesar cipher. You apply that, understand how it works, and solve it again manually.
    
- **Tip:**
    
    Never just copy the solution. Re-solving after learning is key to retention and skill-building.
    
    Dont waste all your time on just one challenge, similar to how you would answer in a exam. Skip it, and try to solve other challenges and come back after you can think of it.
    

---

### **6. Should I prioritize speed or understanding?**

- **Format:**
    
    Speed helps early in a CTF. Deep understanding is needed for tougher, high-point challenges.
    
- **Example:**
    - Easy challenge: Find a flag in plain-text source code.
    - Hard challenge: Requires reversing a binary with no strings or symbols.
- **Tip:**
    
    Practice fast solving for familiar patterns, but always train your understanding. Efficiency comes from combining both.
    

---

### **7. Can I use writeups during a competition?**

- **Format:**
    
    It depends on the rules. Most online jeopardy-style CTFs allow external resources.
    
- **Example:**
    - In a team CTF, you’re allowed to Google and check old writeups. In a school proctored CTF, you might be restricted to offline tools only.
    - **NO AI**, Please if you are going to be using AI don't just copy and paste the problem and ask it how to solve it. You wont learn anything and you are just going to be reliant on it.
- **Tip:**
    
    Always read the event rules. Don’t risk disqualification by using tools or writeups in restricted environments.
    

---

## Weekly CTF Study Planner (Beginner–Intermediate)

- **What it is: Repeat this plan every week with small tweaks as needed.**

[Untitled](Introduction%2022e3dc4f1a94812eb701faab3a5ccb8d/Untitled%2022e3dc4f1a94819c8cc4f94f9b8edfad.csv)

---

## **Resources**

- General Information

---

[https://www.youtube.com/watch?v=8ev9ZX9J45A](https://www.youtube.com/watch?v=8ev9ZX9J45A)

[https://www.youtube.com/watch?v=Zw25_ySOrC0](https://www.youtube.com/watch?v=Zw25_ySOrC0)

[https://www.youtube.com/watch?v=nCMGIR8V-NE](https://www.youtube.com/watch?v=nCMGIR8V-NE)

## Comments about this page (Feel free to add, still trying to fix)

- xxx
- xxx
- xxx