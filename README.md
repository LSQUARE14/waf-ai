# AI based WAF

This is an AI system (kinda like a plugin) that aims at:
- Supporting multiple open-source WAF systems on the market.
- Detecting:
    - Chain attacks
    - Complex payloads 
    - 0-day & 1-day exploits (every one has a dream, right ?)
  
## Author

- Tran Dinh Hoang Long
- Thai Phan Minh Hoang
- Le Dinh Vu
- Tran Duy Long

## Specs

For demonstration, we use **ModSecurity WAF** as a based WAF with blank `.conf` file to demonstrate how the MCP server will produce additional and adaptive rules for the attack context. Relevant system information wil be updated over time.

## Prequisites
- Docker Engine

## Setup

1. After cloning the project, navigate to `/project` where the `docker-compose.yaml` file located.
3. Running the command `docker compose up -d --build`
4. Acccess the WAF at `localhost:8000`

## Current stage & Prgress

- [X] Demonstrated WAF system is completed.
- [ ] Merging the LM and LLM models.
- [ ] Building APIs for the WAF and the whole AI system.
- [ ] Adding web services as victim roles in demonstration.
- [ ] Categorizing and grouping rules by their related vulnerabilities.
- [ ] Add cache module.

Updates are on their way as we will add more features for this kinda-plugin AI thing.

