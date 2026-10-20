# Sandy context boundary

`context.py` imports the actual Hermes threat scanner and write-origin implementation from this checkout. It screens bounded source-labelled context before Sandy includes it in its prompt. It does not start Hermes agent, memory, task, permission or scheduling systems. Rejection is a precaution, not a proof that accepted text is safe. Sandy retains its own action approvals.
