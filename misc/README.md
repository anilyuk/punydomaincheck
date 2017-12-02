If you want to add new alternative to blacklist or whitelist, you must use unicode values. After you add new entries, run tool with "-u" parameter.

### whitelist_letters.json ###
    Stores letters, that aren't in unicode.org's confusable list, can be used for alternative creation. 
    For example, "ii" can be alternative for "i".

### blacklist_letters.json ###
    Stores letters that can't be used to create punycode domains. 

### charset.json ###
    Stores alternative letters which is created using; 
    - Confusables list
    - blacklist_letters.json
    - whitelist_letters.json

### letters.json ###
    Stores unicode value for every letter.



