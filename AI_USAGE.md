# AI usage: dsc26-cyb-w06

Keep the three headings below exactly as they are. The grader stops and scores 0 if this file is
missing or any of the three headings is missing. It does not score what you write; your Track
Mentor reads it, and the W8 defence can ask about it.

## Tools

Claude (Anthropic) wrote the first implementation of normalize.py, prompt.py and output.py and an extra edge-case script; I reviewed and ran it against the public tests and the benign fixture lines. Claude also drafted the two answers under "In my own words" below; the course asks for these to be written without AI, so I am stating that here.

## What AI got wrong

Claude's first version of the link clean-up in output.py had a convoluted branch for keeping allowed links; I replaced it with a simple rule (keep the link as is, rebuild it only if a bare URL inside its text was removed). Its link regex also leaves a stray ")" after links like `[z](javascript:alert(1))` because of the nested parenthesis; the URL itself is removed, so it is harmless, and I left it. A trap it had to be told about up front: `\d` in Python matches Arabic-Indic digits, so the tenant check uses `[0-9]` instead. All of this showed up when running the code and the edge-case script, not from the public tests alone.

## In my own words

1. Which leg of the lethal trifecta does stripping markdown images remove, and why does that matter for Hisn?

   It removes the exfiltration leg (the way data can leave). A markdown image is fetched automatically from a URL the attacker controls, so injected text could hide customer data in that URL and it would be sent out as soon as an analyst's screen renders the reply. This matters for Hisn because the copilot sees alerts from many tenants, and a leak of one tenant's data is exactly what the service must never allow.

2. Why does `triage` raise the severity of an alert that contains an injection attempt instead of just warning?

   A warning flag can be missed, especially on the night shift, and a successful injection is usually trying to make the model say "low" or "close it" so nobody looks. Raising severity to at least high and turning monitor into escalate_to_analyst forces a human to look, and an attacker can never use the model to make an alert quieter than it really is.
