const dns = require('dns/promises');
const spfParse = require('spf-parse');

// DATABASE of major Email Service Providers
const providerDb = {
    'generic': { name: 'Generic / Other', dkimSelectors: ['selector1', 'selector2', 'default', 'k1'] },
    'google-workspace': { name: 'Google Workspace', dkimSelectors: ['google'] },
    'microsoft365': { name: 'Microsoft 365', dkimSelectors: ['selector1', 'selector2'] },
    'mailchimp': { name: 'Mailchimp', dkimSelectors: ['k2', 'k3'] },
    'sendgrid': { name: 'SendGrid', dkimSelectors: ['s1', 's2', 'm1'] },
    'klaviyo': { name: 'Klaviyo', dkimSelectors: ['klaviyo'] },
    'hubspot': { name: 'HubSpot', dkimSelectors: ['hubspot', 'hs1'] },
    'brevo': { name: 'Brevo (Sendinblue)', dkimSelectors: ['mail'] },
    'mailerlite': { name: 'MailerLite', dkimSelectors: ['ml'] },
    'postmark': { name: 'Postmark', dkimSelectors: ['postmark'] },
    'mailgun': { name: 'Mailgun', dkimSelectors: ['mg', 'k1'] },
    'amazonses': { name: 'Amazon SES', dkimSelectors: [] }, // Usually requires custom setup
};

// --- Main Handler ---
module.exports = async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    if (req.method === 'OPTIONS') return res.status(200).end();
    
    const { domain, esp = 'generic' } = req.query;
    if (!domain) return res.status(400).json({ error: 'Domain is required' });

    try {
        const results = await Promise.all([
            checkSpf(domain),
            checkDkim(domain, esp),
            checkDmarc(domain),
            checkMx(domain),
            checkTxtRecord(`default._bimi.${domain}`, 'BIMI', r => r.startsWith('v=BIMI1')),
            checkTxtRecord(`_mta-sts.${domain}`, 'MTA-STS', r => r.startsWith('v=STS1')),
        ]);
        
        const [spf, dkim, dmarc, mx, bimi, mtaSts] = results;
        res.status(200).json({ spf, dkim, dmarc, mx, bimi, mtaSts });

    } catch (error) {
        res.status(500).json({ error: 'An unexpected error occurred during analysis.', details: error.message });
    }
};

// --- Resilient Check Functions ---

// Each function now has its own robust try/catch block
async function checkTxtRecord(query, name, validator) {
    try {
        const records = await dns.resolveTxt(query);
        const record = records.flat().find(validator);
        return record
            ? { status: 'pass', name, info: `Valid ${name} record found.`, record }
            : { status: 'fail', name, info: `${name} record not found.` };
    } catch (error) {
        if (error.code === 'ENODATA' || error.code === 'ENOTFOUND') {
            return { status: 'fail', name, info: `${name} record not found.` };
        }
        return { status: 'error', name, info: 'DNS query error.' };
    }
}

async function checkMx(domain) {
    try {
        const records = await dns.resolveMx(domain);
        return (records && records.length > 0)
            ? { status: 'pass', name: 'MX', info: `${records.length} mail server(s) found.`, records }
            : { status: 'fail', name: 'MX', info: 'No MX records found.' };
    } catch (error) {
        if (error.code === 'ENODATA') return { status: 'fail', name: 'MX', info: 'No MX records found.' };
        return { status: 'error', name: 'MX', info: 'DNS query error.' };
    }
}

async function checkSpf(domain) {
    const result = { name: 'SPF', status: 'fail', info: 'No SPF record found.', mechanisms: [], warnings: [] };
    try {
        const records = await dns.resolveTxt(domain);
        const spfRecords = records.flat().filter(r => r.toLowerCase().startsWith('v=spf1'));
        if (spfRecords.length === 0) return result;
        if (spfRecords.length > 1) {
            result.warnings.push('Critical: Multiple SPF records found. Only one is allowed.');
            result.info = 'Multiple SPF records found.';
            return result;
        }

        const parsed = spfParse(spfRecords[0]);
        result.status = parsed.valid ? 'pass' : 'fail';
        result.info = parsed.valid ? 'SPF record syntax is valid.' : 'SPF record has syntax errors.';
        result.mechanisms = parsed.mechanisms;

        const lookupMechanisms = (spfRecords[0].match(/(include:|a:|mx:|exists:|redirect=)/g) || []).length;
        if (lookupMechanisms > 10) {
            result.status = 'fail';
            result.warnings.push(`Critical: ${lookupMechanisms} DNS lookups found, exceeding the limit of 10.`);
        }
        return result;
    } catch (error) {
        if (error.code === 'ENODATA') return result;
        return { status: 'error', name: 'SPF', info: 'DNS query error.' };
    }
}

async function checkDkim(domain, esp) {
    try {
        const selectors = providerDb[esp]?.dkimSelectors || providerDb['generic'].dkimSelectors;
        for (const selector of selectors) {
            const query = `${selector}._domainkey.${domain}`;
            try {
                const records = await dns.resolveTxt(query);
                const record = records.flat().find(r => r.startsWith('v=DKIM1'));
                if (record) {
                    return { status: 'pass', name: 'DKIM', info: `Key found with selector: '${selector}'.`, record };
                }
            } catch (e) { /* Ignore individual selector failures */ }
        }
        return { status: 'fail', name: 'DKIM', info: 'No DKIM key found for common or provider-specific selectors.' };
    } catch (error) {
        return { status: 'error', name: 'DKIM', info: 'DNS query error.' };
    }
}

async function checkDmarc(domain) {
    try {
        const records = await dns.resolveTxt(`_dmarc.${domain}`);
        const record = records.flat().find(r => r.startsWith('v=DMARC1'));
        if (!record) return { name: 'DMARC', status: 'fail', info: 'No DMARC record found.' };

        const policy = record.match(/p=([^;]+)/);
        if (policy) {
            return {
                status: 'pass',
                name: 'DMARC',
                info: `DMARC policy is set to "${policy[1]}".`,
                policy: policy[1],
                rua: record.includes('rua='),
                record
            };
        }
        return { name: 'DMARC', status: 'fail', info: 'DMARC record found, but required "p" (policy) tag is missing.', record };
    } catch (error) {
        if (error.code === 'ENODATA' || error.code === 'ENOTFOUND') {
            return { name: 'DMARC', status: 'fail', info: 'No DMARC record found.' };
        }
        return { status: 'error', name: 'DMARC', info: 'DNS query error.' };
    }
}
