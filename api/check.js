// Our powerful backend engine. It uses Node.js's built-in DNS module.
const dns = require('dns/promises');
const spfParse = require('spf-parse');

// --- Main Handler Function ---
// This is the function Vercel will run when our webpage calls the API.
module.exports = async (req, res) => {
  // Set headers to allow our webpage to talk to this API
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // Handle pre-flight requests for browsers
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  const domain = req.query.domain;
  if (!domain) {
    return res.status(400).json({ error: 'Domain is required' });
  }

  try {
    // Run all our checks in parallel for maximum speed
    const [spf, dmarc, dkim, mx, bimi, mtaSts] = await Promise.all([
      checkSpf(domain),
      checkDmarc(domain),
      checkDkim(domain),
      checkMx(domain),
      checkTxtRecord(`default._bimi.${domain}`, 'BIMI', r => r.startsWith('v=BIMI1')),
      checkTxtRecord(`_mta-sts.${domain}`, 'MTA-STS', r => r.startsWith('v=STS1')),
    ]);
    
    // Send the final, clean report back to our webpage
    res.status(200).json({ spf, dmarc, dkim, mx, bimi, mtaSts });

  } catch (error) {
    res.status(500).json({ error: 'An error occurred during analysis.', details: error.message });
  }
};


// --- Individual Check Functions ---

async function checkTxtRecord(query, name, validator) {
  try {
    const records = await dns.resolveTxt(query);
    const record = records.flat().find(validator);
    if (record) {
      return { status: 'pass', name, info: 'Valid record found.', record };
    }
    return { status: 'fail', name, info: 'Record not found.' };
  } catch (error) {
    if (error.code === 'ENODATA' || error.code === 'ENOTFOUND') {
      return { status: 'fail', name, info: 'Record not found.' };
    }
    return { status: 'error', name, info: 'DNS query failed.', error: error.message };
  }
}

async function checkMx(domain) {
    try {
        const records = await dns.resolveMx(domain);
        if (records && records.length > 0) {
            return { status: 'pass', name: 'MX', info: `${records.length} record(s) found.`, records };
        }
        return { status: 'fail', name: 'MX', info: 'No MX records found.' };
    } catch (error) {
        if (error.code === 'ENODATA') {
            return { status: 'fail', name: 'MX', info: 'No MX records found.' };
        }
        return { status: 'error', name: 'MX', info: 'DNS query failed.', error: error.message };
    }
}

async function checkSpf(domain) {
  const result = { name: 'SPF', status: 'fail', info: 'No SPF record found.', mechanisms: [], warnings: [] };
  try {
    const records = await dns.resolveTxt(domain);
    const rawSpf = records.flat().find(r => r.toLowerCase().startsWith('v=spf1'));
    if (!rawSpf) return result;

    const parsed = spfParse(rawSpf);
    result.status = parsed.valid ? 'pass' : 'fail';
    result.info = parsed.valid ? 'SPF record is valid.' : 'SPF record has syntax errors.';
    result.mechanisms = parsed.mechanisms;

    if (records.flat().filter(r => r.toLowerCase().startsWith('v=spf1')).length > 1) {
        result.status = 'fail';
        result.warnings.push('Critical: Multiple SPF records found. Only one is allowed.');
    }
    const lookupMechanisms = (rawSpf.match(/(include:|a:|mx:|exists:|redirect=)/g) || []).length;
    if (lookupMechanisms > 10) {
        result.status = 'fail';
        result.warnings.push(`Critical: ${lookupMechanisms} DNS lookups found, exceeding the limit of 10.`);
    }

    return result;
  } catch (error) {
     if (error.code === 'ENODATA') return result; // No TXT records found at all
     return { status: 'error', name: 'SPF', info: 'DNS query failed.', error: error.message };
  }
}

async function checkDmarc(domain) {
    const result = { name: 'DMARC', status: 'fail', info: 'No DMARC record found.' };
    try {
        const records = await dns.resolveTxt(`_dmarc.${domain}`);
        const record = records.flat().find(r => r.startsWith('v=DMARC1'));
        if (!record) return result;

        result.record = record;
        const policy = record.match(/p=([^;]+)/);
        if (policy) {
            result.status = 'pass';
            result.policy = policy[1];
            result.info = `Policy is set to "${result.policy}".`;
        } else {
            result.info = 'DMARC record found, but required "p" (policy) tag is missing.';
        }
        if (record.includes('rua=')) result.rua = true;

        return result;
    } catch (error) {
        if (error.code === 'ENODATA' || error.code === 'ENOTFOUND') return result;
        return { status: 'error', name: 'DMARC', info: 'DNS query failed.', error: error.message };
    }
}

async function checkDkim(domain) {
    // We check a few common selectors. This is a heuristic, as the actual selector
    // is in the email header, which we can't access.
    const commonSelectors = ['google', 'selector1', 'selector2', 'k1', 'k2', 'k3', 'default', 'mail', 'dkim'];
    for (const selector of commonSelectors) {
        try {
            const query = `${selector}._domainkey.${domain}`;
            const records = await dns.resolveTxt(query);
            const record = records.flat().find(r => r.startsWith('v=DKIM1'));
            if (record) {
                return { status: 'pass', name: 'DKIM', info: `Key found with selector: '${selector}'.`, selector, record };
            }
        } catch (error) {
            // Ignore ENODATA errors and continue loop
            if (error.code !== 'ENODATA' && error.code !== 'ENOTFOUND') {
                console.error(`DKIM check failed for ${selector}:`, error.message);
            }
        }
    }
    return { status: 'fail', name: 'DKIM', info: 'No DKIM key found for common selectors.' };
}
