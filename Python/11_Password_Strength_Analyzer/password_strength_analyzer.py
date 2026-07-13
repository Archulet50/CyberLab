#!/usr/bin/env python3 

 

import getpass 

import re 

 

COMMON_PASSWORDS = { 

    "password", 

    "password123", 

    "123456", 

    "12345678", 

    "qwerty", 

    "admin", 

    "letmein", 

    "welcome", 

    "iloveyou", 

} 

 

 

def analyze_password(password: str) -> tuple[int, list[str], list[str]]: 

    score = 0 

    strengths = [] 

    recommendations = [] 

 

    if len(password) >= 16: 

        score += 3 

        strengths.append("Excellent length: 16 or more characters") 

    elif len(password) >= 12: 

        score += 2 

        strengths.append("Good length: 12 or more characters") 

    elif len(password) >= 8: 

        score += 1 

        strengths.append("Minimum acceptable length") 

    else: 

        recommendations.append("Use at least 12 characters") 

 

    if re.search(r"[a-z]", password): 

        score += 1 

        strengths.append("Contains lowercase letters") 

    else: 

        recommendations.append("Add lowercase letters") 

 

    if re.search(r"[A-Z]", password): 

        score += 1 

        strengths.append("Contains uppercase letters") 

    else: 

        recommendations.append("Add uppercase letters") 

 

    if re.search(r"\d", password): 

        score += 1 

        strengths.append("Contains numbers") 

    else: 

        recommendations.append("Add numbers") 

 

    if re.search(r"[^A-Za-z0-9]", password): 

        score += 1 

        strengths.append("Contains special characters") 

    else: 

        recommendations.append("Add special characters") 

 

    if password.lower() in COMMON_PASSWORDS: 

        score -= 4 

        recommendations.append("Do not use a common password") 

 

    if re.search(r"(.)\1{2,}", password): 

        score -= 1 

        recommendations.append("Avoid repeated characters such as aaa or 111") 

 

    if re.search(r"1234|abcd|qwerty|password|admin", password.lower()): 

        score -= 2 

        recommendations.append("Avoid predictable words and sequences") 

 

    score = max(0, min(score, 8)) 

 

    return score, strengths, recommendations 

 

 

def rating_from_score(score: int) -> str: 

    if score <= 2: 

        return "VERY WEAK" 

    if score <= 4: 

        return "WEAK" 

    if score <= 6: 

        return "MODERATE" 

    if score == 7: 

        return "STRONG" 

    return "VERY STRONG" 

 

 

print("=" * 60) 

print("       CYBERLAB PASSWORD STRENGTH ANALYZER") 

print("=" * 60) 

 

print("\nUse a test password—not a real account password.") 

password = getpass.getpass("Enter password to analyze: ") 

 

score, strengths, recommendations = analyze_password(password) 

rating = rating_from_score(score) 

 

print("\nAnalysis Results") 

print("-" * 60) 

print(f"Score  : {score}/8") 

print(f"Rating : {rating}") 

 

print("\nStrengths") 

print("-" * 60) 

 

if strengths: 

    for item in strengths: 

        print(f"[+] {item}") 

else: 

    print("[-] No significant strengths detected") 

 

print("\nRecommendations") 

print("-" * 60) 

 

if recommendations: 

    for item in recommendations: 

        print(f"[!] {item}") 

else: 

    print("[+] No major improvements recommended") 
