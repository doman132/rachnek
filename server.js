// Backend dla integracji Gmail API i Przelewy24
const express = require('express');
const cors = require('cors');
const { google } = require('googleapis');
const session = require('express-session');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();

// CORS Configuration - pozwala na credentials
const corsOptions = {
    origin: ['http://localhost:3000', 'http://127.0.0.1:5500', 'http://localhost:5500', 'file://'],
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json());

// Serve static files (HTML, CSS, JS) from current directory
app.use(express.static(__dirname));

app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: true,
    saveUninitialized: true,
    cookie: {
        secure: false, // Set to false for localhost (no HTTPS)
        httpOnly: true,
        sameSite: 'lax', // Allows cookies in cross-origin requests
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Google OAuth2 setup
const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3001/auth/callback'
);

// Generuj URL do logowania
app.get('/auth/google', (req, res) => {
    const authUrl = oauth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: ['https://www.googleapis.com/auth/gmail.readonly'],
        prompt: 'consent'
    });
    res.json({ authUrl });
});

// Callback po zalogowaniu
app.get('/auth/callback', async (req, res) => {
    const { code } = req.query;
    try {
        const { tokens } = await oauth2Client.getToken(code);
        req.session.tokens = tokens;
        oauth2Client.setCredentials(tokens);
        
        console.log('✅ OAuth2 Callback - Tokeny zapisane w sesji');
        console.log('📝 Session ID:', req.sessionID);
        
        // Zapisz sesję przed wysłaniem odpowiedzi
        req.session.save((err) => {
            if (err) {
                console.error('❌ Błąd zapisywania sesji:', err);
            } else {
                console.log('✅ Sesja zapisana pomyślnie');
            }
        });
        
        // Wysłij HTML z kodem aby powiadomić popup
        res.send(`
            <html>
                <head><title>Zalogowano</title></head>
                <body>
                    <h1>✅ Zalogowano pomyślnie!</h1>
                    <p>Możesz zamknąć to okno.</p>
                    <script>
                        // Powiadom parent window że login się udał
                        window.opener.postMessage({ type: 'gmail-login-success' }, '*');
                        window.setTimeout(() => window.close(), 1500);
                    </script>
                </body>
            </html>
        `);
    } catch (error) {
        console.error('OAuth Error:', error);
        res.send(`
            <html>
                <head><title>Błąd logowania</title></head>
                <body>
                    <h1>❌ Błąd logowania</h1>
                    <p>${error.message}</p>
                    <script>
                        window.opener.postMessage({ type: 'gmail-login-failed', error: '${error.message}' }, '*');
                        window.setTimeout(() => window.close(), 2000);
                    </script>
                </body>
            </html>
        `);
    }
});

// Pobierz rachunki z Gmaila
app.get('/api/bills/fetch', async (req, res) => {
    try {
        console.log('📥 Fetch bills request...');
        
        if (!req.session.tokens) {
            console.error('❌ Brak tokenów w sesji!');
            return res.status(401).json({ error: 'Nie jesteś zalogowany' });
        }

        console.log('✅ Tokeny znalezione');

        oauth2Client.setCredentials(req.session.tokens);
        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

        // Oblicz datę sprzed miesiąca
        const oneMonthAgo = new Date();
        oneMonthAgo.setMonth(oneMonthAgo.getMonth() - 1);
        const oneMonthAgoStr = oneMonthAgo.toISOString().split('T')[0]; // Format: YYYY-MM-DD
        
        console.log(`🔍 Szukam rachunków od ${oneMonthAgoStr}`);

        // Szukaj wiadomości zawierających słowa "rachunek", "invoice", "billing", "E-Faktura"
        // Nie ograniczaj do is:unread, bo pobrane poprzednio będą już przeczytane
        // after: pobiera wiadomości od danej daty
        const messages = await gmail.users.messages.list({
            userId: 'me',
            q: `subject:(rachunek OR invoice OR billing OR račun OR "E-Faktura") after:${oneMonthAgoStr}`,
            maxResults: 20
        });

        console.log(`📧 Znaleziono ${messages.data.messages ? messages.data.messages.length : 0} wiadomości`);

        const bills = [];

        if (messages.data.messages) {
            for (const message of messages.data.messages) {
                const msg = await gmail.users.messages.get({
                    userId: 'me',
                    id: message.id,
                    format: 'full'
                });

                const headers = msg.data.payload.headers;
                const from = headers.find(h => h.name === 'From')?.value || 'Unknown';
                const subject = headers.find(h => h.name === 'Subject')?.value || 'No subject';
                const date = headers.find(h => h.name === 'Date')?.value || new Date();

                console.log(`  📌 ${subject}`);

                // Funkcja do wydobywania kwoty z tekstu
                function extractAmount(text) {
                    if (!text) return 0;
                    
                    console.log(`      🔍 Szukam kwot w tekście:`);
                    
                    let bestAmount = 0;
                    let foundAmount = false;
                    
                    // NAJPIERW szukaj kwot które mają SŁOWA KLUCZOWE (najważniejsze)
                    const keywordPattern = /(?:kwota|do\s?zapłaty|razem|suma|total|amount|wartość|należność|koszt|cena|factura|invoice)[\s:]+(\d+(?:[\s.,]\d{3})*[.,]\d{2})\s*(?:zł|pln|zl|€|eur|usd|\$)?/gi;
                    let match;
                    const keywordMatches = [];
                    
                    while ((match = keywordPattern.exec(text)) !== null) {
                        let numStr = match[1].replace(/[\s]/g, '').replace(',', '.');
                        let amount = parseFloat(numStr);
                        if (amount > 0.01 && amount < 100000) {
                            keywordMatches.push(amount);
                            console.log(`        ✓ Ze słowa kluczowego: ${amount} zł`);
                        }
                    }
                    
                    // Jeśli znaleźliśmy kwoty ze słów kluczowych, użyj NAJWIĘKSZĄ z nich
                    if (keywordMatches.length > 0) {
                        bestAmount = Math.max(...keywordMatches);
                        foundAmount = true;
                        console.log(`      ✅ Wybrana kwota ze słów kluczowych: ${bestAmount} zł`);
                        return Math.round(bestAmount * 100) / 100;
                    }
                    
                    // DRUGIE - szukaj liczb z walutą/symbolem
                    const currencyPattern = /(\d+(?:[\s.,]\d{3})*[.,]\d{2})[\s]*(zł|pln|zl|€|eur|usd|\$)/gi;
                    const currencyMatches = [];
                    keywordPattern.lastIndex = 0; // Reset
                    
                    while ((match = currencyPattern.exec(text)) !== null) {
                        let numStr = match[1].replace(/[\s]/g, '').replace(',', '.');
                        let amount = parseFloat(numStr);
                        if (amount > 0.01 && amount < 100000) {
                            currencyMatches.push(amount);
                            console.log(`        ✓ Z walutą: ${amount} zł`);
                        }
                    }
                    
                    if (currencyMatches.length > 0) {
                        bestAmount = Math.max(...currencyMatches);
                        foundAmount = true;
                        console.log(`      ✅ Wybrana kwota z waluty: ${bestAmount} zł`);
                        return Math.round(bestAmount * 100) / 100;
                    }
                    
                    // TRZECIE - szukaj samych liczb (mniej niezawodne)
                    const numberPattern = /(\d+(?:[\s.,]\d{3})*[.,]\d{2})/g;
                    const numberMatches = [];
                    
                    while ((match = numberPattern.exec(text)) !== null) {
                        let numStr = match[1].replace(/[\s]/g, '').replace(',', '.');
                        let amount = parseFloat(numStr);
                        // Filtruj liczby, które wyglądają sensownie
                        if (amount > 0.01 && amount < 100000) {
                            // Unikaj liczb które wyglądają na daty (np. 2024.01.22)
                            if (!(amount > 1900 && amount < 2100)) {
                                numberMatches.push(amount);
                                console.log(`        ○ Liczba: ${amount} zł`);
                            }
                        }
                    }
                    
                    if (numberMatches.length > 0) {
                        // Bierz pierwszą rozsądną liczbę zamiast największej
                        // (bo czasem są liczby z NIP, daty itp)
                        bestAmount = numberMatches.find(n => n > 10 && n < 50000) || Math.max(...numberMatches);
                        console.log(`      ✅ Wybrana kwota z liczb: ${bestAmount} zł`);
                        return Math.round(bestAmount * 100) / 100;
                    }
                    
                    if (!foundAmount) {
                        console.log(`      ❌ Brak kwot znalezionych`);
                    }
                    return 0;
                }

                // Pobierz treść wiadomości - spróbuj różne formaty
                let body = '';
                
                // Rekurencyjna funkcja do znalezienia treści w zagnieżdżonych parts
                function extractBodyFromParts(parts) {
                    if (!parts) return '';
                    
                    // Spróbuj najpierw text/plain
                    let part = parts.find(p => p.mimeType === 'text/plain');
                    if (part && part.body && part.body.data) {
                        return Buffer.from(part.body.data, 'base64').toString('utf-8');
                    }
                    
                    // Potem text/html
                    part = parts.find(p => p.mimeType === 'text/html');
                    if (part && part.body && part.body.data) {
                        let htmlContent = Buffer.from(part.body.data, 'base64').toString('utf-8');
                        // Oczyść HTML z tagów
                        return htmlContent
                            .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')  // Usuń scripts
                            .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')    // Usuń styles
                            .replace(/<[^>]*>/g, ' ')                         // Usuń pozostałe tagi HTML
                            .replace(/&nbsp;/g, ' ')
                            .replace(/&quot;/g, '"')
                            .replace(/&amp;/g, '&')
                            .replace(/&lt;/g, '<')
                            .replace(/&gt;/g, '>')
                            .replace(/\s+/g, ' ')
                            .trim();
                    }
                    
                    // Spróbuj rekurencyjnie w zagnieżdżonych parts
                    for (const p of parts) {
                        if (p.parts) {
                            const nested = extractBodyFromParts(p.parts);
                            if (nested) return nested;
                        }
                    }
                    
                    return '';
                }
                
                // Ekstrakcja z payload
                if (msg.data.payload.parts) {
                    body = extractBodyFromParts(msg.data.payload.parts);
                } else if (msg.data.payload.body && msg.data.payload.body.data) {
                    body = Buffer.from(msg.data.payload.body.data, 'base64').toString('utf-8');
                }

                console.log(`    📧 ===== PEŁNA TREŚĆ EMAILA =====`);
                console.log(body);
                console.log(`    ===== KONIEC TREŚCI =====\n`);

                // Wydobyj kwotę - NAJPIERW Z TREŚCI
                let amount = extractAmount(body);
                
                // Jeśli w treści nie ma kwoty, spróbuj Subject jako fallback
                if (amount === 0) {
                    console.log(`    ⚠️ Brak kwoty w treści, szukam w temacie...`);
                    amount = extractAmount(subject);
                }
                
                // Formatuj kwotę na zawsze 2 miejsca po przecinku
                const formattedAmount = parseFloat(amount).toFixed(2);
                console.log(`\n    💰 ===== OSTATECZNA KWOTA: ${formattedAmount} zł =====\n`);

                // Spróbuj wydobyć datę terminu
                let dueDate = new Date();
                dueDate.setDate(dueDate.getDate() + 30); // Default 30 dni od teraz
                
                console.log(`    🔍 ===== SZUKAM TERMINU ZAPŁATY =====`);
                
                // Pobierz WSZYSTKIE daty znalezione w emailu
                const allDates = body.match(/(\d{2}\.\d{2}\.\d{4})/g) || [];
                console.log(`    📅 WSZYSTKIE znalezione daty (DD.MM.YYYY): ${allDates.length > 0 ? allDates.join(', ') : 'BRAK'}`);
                
                let foundDate = false;
                let dateMatch = null;
                
                // Helper function to convert DD.MM.YYYY string directly to YYYY-MM-DD
                const convertDateFormat = (ddmmyyyy) => {
                    const [day, month, year] = ddmmyyyy.split('.');
                    return `${year}-${month}-${day}`;
                };
                
                // Metoda 1: Szukaj daty bezpośrednio po słowach kluczowych "zapłać" lub "termin"
                // Pattern: słowo kluczowe + opcjonalny tekst + data
                const keywordDateMatch = body.match(/(?:zapłać\s+do|termin\s+zapłaty|termin\s+płatności|do\s+zapłacenia)\s+(\d{2}\.\d{2}\.\d{4})/i);
                if (keywordDateMatch && keywordDateMatch[1]) {
                    const dateString = convertDateFormat(keywordDateMatch[1]);
                    dueDate = dateString;
                    console.log(`    ✅ ZNALEZIONO datę po słowie kluczowym: ${keywordDateMatch[1]} -> ${dueDate}`);
                    foundDate = true;
                }
                
                // Metoda 2: Jeśli pierwsza metoda nie zadziałała, szukaj w liniach zawierających słowa kluczowe
                if (!foundDate) {
                    const bodyLines = body.split('\n');
                    console.log(`    📄 Liczba linii w emailu: ${bodyLines.length}`);
                    
                    for (let i = 0; i < bodyLines.length; i++) {
                        const line = bodyLines[i];
                        if (line.match(/zapłać|termin|do\s+(zapłat|płat|zap|przelewu|spłat)|deadline|due.*date|date.*due|płatność|należy|należności/i)) {
                            console.log(`    📝 Linia ${i}: "${line.trim()}"`);
                            
                            dateMatch = line.match(/(\d{2}\.\d{2}\.\d{4})/);
                            if (dateMatch) {
                                const dateString = convertDateFormat(dateMatch[0]);
                                dueDate = dateString;
                                console.log(`    ✅ ZNALEZIONO datę z linii: ${dateMatch[0]} -> ${dueDate}`);
                                foundDate = true;
                                break;
                            }
                        }
                    }
                }
                
                // Metoda 3: Jeśli nie znaleziono daty w liniach z słowami kluczowymi, weź OSTATNIĄ datę z emailu
                if (!foundDate && allDates.length > 0) {
                    console.log(`    ℹ️ Nie znaleziono daty w liniach z terminem, biorę OSTATNIĄ znalezioną datę`);
                    const lastDate = allDates[allDates.length - 1];
                    const dateString = convertDateFormat(lastDate);
                    dueDate = dateString;
                    console.log(`    ✅ OSTATNIA data: ${lastDate} -> ${dueDate}`);
                    foundDate = true;
                }
                
                if (!foundDate) {
                    console.log(`    ℹ️ Nie znaleziono żadnej daty, używam domyślnie 30 dni`);
                }
                
                console.log(`    📅 ===== OSTATECZNY TERMIN: ${dueDate} =====\n`);
                bills.push({
                    id: `gmail_${message.id}`,
                    name: subject.substring(0, 50),
                    amount: amount || 0,
                    due: dueDate,
                    category: 'Other',
                    paid: false,
                    source: from,
                    messageId: message.id
                });
            }
        }

        console.log(`✅ Zwracam ${bills.length} rachunków`);
        res.json({ bills, count: bills.length });
    } catch (error) {
        console.error('❌ BŁĄD w fetchEmailBills:', error.message);
        console.error(error);
        res.status(500).json({ error: error.message, details: error.toString() });
    }
});

// Pobierz profil użytkownika
app.get('/api/user/profile', async (req, res) => {
    try {
        if (!req.session.tokens) {
            return res.status(401).json({ error: 'Nie jesteś zalogowany' });
        }

        oauth2Client.setCredentials(req.session.tokens);
        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

        const profile = await gmail.users.getProfile({
            userId: 'me'
        });

        res.json({ 
            email: profile.data.emailAddress,
            messagesTotal: profile.data.messagesTotal
        });
    } catch (error) {
        console.error('Error fetching profile:', error);
        res.status(500).json({ error: error.message });
    }
});

// Logout
app.post('/auth/logout', (req, res) => {
    req.session.destroy();
    res.json({ message: 'Wylogowano pomyślnie' });
});

// ========== PRZELEWY24 PAYMENT INTEGRATION ==========

// Przelewy24 Configuration
const P24_MERCHANT_ID = process.env.P24_MERCHANT_ID || '100026342'; // Test merchant ID
const P24_API_KEY = process.env.P24_API_KEY || 'e6722cb0c6e8ea5c28f2fb49c97ea14c'; // Test API key
const P24_CRC_KEY = process.env.P24_CRC_KEY || '4634f5ad657b22e4'; // Test CRC key
const P24_SANDBOX = process.env.P24_SANDBOX !== 'false'; // Use sandbox by default
const P24_BASE_URL = P24_SANDBOX ? 'https://sandbox.przelewy24.pl' : 'https://secure.przelewy24.pl';

// Funkcja do generowania sygnatury dla Przelewy24
function generateP24Signature(data) {
    const sortedKeys = Object.keys(data).sort();
    let signatureString = '';
    
    for (const key of sortedKeys) {
        signatureString += data[key];
    }
    
    signatureString += P24_CRC_KEY;
    return crypto.createHash('md5').update(signatureString).digest('hex');
}

// Endpoint: Inicjuj płatność
app.post('/api/payment/create', async (req, res) => {
    try {
        const { billId, billName, amount, email, returnUrl } = req.body;
        
        if (!billId || !amount || !email) {
            return res.status(400).json({ error: 'Brakuje wymaganych pól' });
        }
        
        // Konwertuj kwotę do groszy (Przelewy24 przyjmuje grosze)
        const amountInGroszy = Math.round(amount * 100);
        
        // Generuj unikatowy numer transakcji
        const sessionId = uuidv4().replace(/-/g, '').substring(0, 24);
        
        const paymentData = {
            p24_merchant_id: P24_MERCHANT_ID,
            p24_session_id: sessionId,
            p24_amount: amountInGroszy,
            p24_currency: 'PLN',
            p24_description: billName || 'Płatność rachunku',
            p24_email: email,
            p24_client: 'BillsApp',
            p24_address: 'n/a',
            p24_zip: '00-000',
            p24_city: 'n/a',
            p24_country: 'PL',
            p24_language: 'pl'
        };
        
        // Generuj sygnaturę
        paymentData.p24_sign = generateP24Signature(paymentData);
        
        console.log('✅ Payment session created:', sessionId);
        console.log('💰 Amount:', amountInGroszy, 'groszy =', amount, 'PLN');
        
        // Przygotuj URL do płatności
        const paymentUrl = new URL(`${P24_BASE_URL}/trnRequest/${P24_MERCHANT_ID}/${sessionId}/${amountInGroszy}/0xpayment`);
        
        // Zwróć dane do frontendu
        res.json({
            paymentUrl: paymentUrl.toString(),
            sessionId: sessionId,
            amount: amount,
            redirectUrl: returnUrl
        });
    } catch (error) {
        console.error('❌ Payment creation error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Endpoint: Weryfikuj płatność (callback z Przelewy24)
app.post('/api/payment/verify', async (req, res) => {
    try {
        const { p24_session_id, p24_order_id, p24_amount } = req.body;
        
        console.log('📩 Payment verification from Przelewy24:', p24_session_id);
        
        if (!p24_session_id) {
            return res.status(400).json({ error: 'Brak session ID' });
        }
        
        // Przygotuj dane do weryfikacji
        const verifyData = {
            p24_merchant_id: P24_MERCHANT_ID,
            p24_session_id: p24_session_id,
            p24_amount: p24_amount,
            p24_currency: 'PLN'
        };
        
        // Generuj sygnaturę do weryfikacji
        verifyData.p24_sign = generateP24Signature(verifyData);
        
        console.log('✅ Verification signature generated');
        
        // W rzeczywistej integracji tutaj byś wysyłał zapytanie do API Przelewy24
        // Na potrzeby demo będziemy akceptować płatność
        res.json({
            status: 'success',
            message: 'Płatność zweryfikowana',
            sessionId: p24_session_id
        });
    } catch (error) {
        console.error('❌ Payment verification error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Endpoint: Oznacz rachunek jako zapłacony
app.post('/api/bills/mark-paid', async (req, res) => {
    try {
        const { billIds, sessionId } = req.body;
        
        if (!billIds || !Array.isArray(billIds)) {
            return res.status(400).json({ error: 'Brakuje billIds' });
        }
        
        console.log('✅ Bills marked as paid:', billIds, 'Payment session:', sessionId);
        
        // W rzeczywistej integracji tutaj byś zapisywał do bazy danych
        // Na potrzeby demo zwracamy potwierdzenie
        res.json({
            status: 'success',
            message: `Oznaczono ${billIds.length} rachunków jako opłacone`,
            paidBills: billIds,
            paymentSession: sessionId
        });
    } catch (error) {
        console.error('❌ Mark bills as paid error:', error);
        res.status(500).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log('Google Client ID:', process.env.GOOGLE_CLIENT_ID ? '✅ OK' : '❌ BRAK!');
    console.log('Google Client Secret:', process.env.GOOGLE_CLIENT_SECRET ? '✅ OK' : '❌ BRAK!');
    console.log('Callback URL:', process.env.GOOGLE_CALLBACK_URL);
});
