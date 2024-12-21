# CS155: Web Security Project

This repository contains my completed implementation of Stanford's CS155 Computer Security course Project #2, which implements various web security attacks and defenses against a Node.js cryptocurrency web application called Bitbar.

## Project Overview

Implemented seven different web security attacks and their corresponding defenses:

### Part 1: Attacks
- Cookie Theft (XSS)
- Cross-Site Request Forgery 
- Session Hijacking
- Cookie Tampering
- SQL Injection
- Profile Worm
- Password Extraction via Timing Attack

### Part 2: Defenses
- XSS Protection
- CSRF Protection
- Cookie Security
- SQL Injection Prevention
- Side-Channel Attack Mitigation

## Technologies Used
- Node.js
- Express.js
- SQLite
- EJS Templating
- Docker

## Notes
- All attacks were tested and verified to work in Firefox
- Defenses were implemented without relying on Express.js built-in protections