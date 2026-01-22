# Menedżer Rachunków - Integracja z Real API

## 🚀 Instalacja

### 1. Setup Google OAuth2 - Krok po Kroku

#### Krok 1: Przejdź do Google Cloud Console
1. Otwórz https://console.cloud.google.com/
2. Zaloguj się na swoje konto Google

#### Krok 2: Utwórz nowy projekt
1. Kliknij na **"Select a Project"** w górnym pasku
2. Kliknij **"NEW PROJECT"** (nowy projekt)
3. Wpisz nazwę: `Bills Manager`
4. Kliknij **CREATE**
5. Czekaj na utworzenie projektu (~1 min)

#### Krok 3: Włącz Gmail API
1. W Search bar (góra) wpisz: `Gmail API`
2. Kliknij na **Gmail API**
3. Kliknij niebieski przycisk **ENABLE**
4. Czekaj na włączenie (~30 sekund)

#### Krok 4: Utwórz OAuth2 Credentials (Web Application)
1. Z menu po lewej kliknij **"Credentials"** (Poświadczenia)
2. Kliknij **"+ CREATE CREDENTIALS"**
3. Wybierz **"OAuth client ID"**

**Jeśli pojawi się okno o "OAuth consent screen":**
1. Kliknij **"CONFIGURE CONSENT SCREEN"**
2. Wybierz **"External"** → kliknij **CREATE**
3. Wypełnij:
   - **App name**: `Bills Manager`
   - **User support email**: Twój email
   - **Developer contact info**: Twój email
4. Kliknij **SAVE AND CONTINUE**
5. Pomiń "Scopes" (kliknij **SAVE AND CONTINUE**)
6. Pomiń "Test users" (kliknij **SAVE AND CONTINUE**)
7. Kliknij **BACK TO DASHBOARD**

#### Krok 5: Utwórz OAuth Client ID
1. Znowu kliknij **Credentials** → **+ CREATE CREDENTIALS** → **OAuth client ID**
2. Wybierz typ: **Web application**
3. Wpisz nazwę: `Bills Manager Web Client`
4. W sekcji **"Authorized redirect URIs"** kliknij **+ ADD URI** i wpisz:
   ```
   http://localhost:3001/auth/callback
   ```
5. Kliknij **CREATE**

#### Krok 6: Pobierz Client ID i Secret
1. Pojawi się okno z danymi
2. **Skopiuj** `Client ID` 
3. **Skopiuj** `Client Secret`

#### Krok 7: Przechowaj w .env
Utwórz plik `.env` w folderze projektu i wpisz:
```
GOOGLE_CLIENT_ID=skopiowany_client_id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=skopiowany_client_secret
GOOGLE_CALLBACK_URL=http://localhost:3001/auth/callback
SESSION_SECRET=jakis_losowy_secret_klucz_np_abc123xyz
PORT=3001
```

### 2. Konfiguracja Backend

```bash
# Zainstaluj zależności
npm install

# Uruchomij backend
npm start
```

**Oczekiwany output:**
```
Server running on http://localhost:3001
```

### 3. Uruchomienie Aplikacji

1. **Terminal 1** - Backend jest już uruchomiony (port 3001)
2. **Terminal 2** - Otwórz aplikację frontend:
   ```bash
   # Otwórz plik w przeglądarce
   file:///c:/Users/Doman/Desktop/apka%20na%20rachunki/index.html
   ```
   
   LUB użyj Live Server w VS Code:
   - Kliknij prawy przycisk na `index.html`
   - Wybierz "Open with Live Server"

## 🔑 API Endpoints

### Autentykacja
- **GET** `/auth/google` - Generuje link do logowania
- **GET** `/auth/callback` - Callback po zalogowaniu
- **POST** `/auth/logout` - Wylogowanie

### Pobieranie Rachunków
- **GET** `/api/bills/fetch` - Pobiera rachunki z Gmaila
- **GET** `/api/user/profile` - Pobiera profil użytkownika

## 📧 Jak to działa

1. Kliknij "🔗 Połącz z Gmaila" w aplikacji
2. Aplikacja otwiera Google Login w nowym oknie
3. Zaloguj się na swoje konto Google
4. Zaakceptuj dostęp (pierwsza autoryzacja)
5. Po zalogowaniu wróć do aplikacji
6. Kliknij "📥 Pobierz rachunki z maila"
7. Aplikacja szuka e-maili zawierających "rachunek", "invoice", "billing"
8. Automatycznie wydobywa kwoty i terminy

## 🔒 Bezpieczeństwo

- Tokeny OAuth2 przechowywane w sesji serwera (nie w przeglądarce)
- Brak ujawniania danych logowania
- Bezpieczny CORS
- Callback URL musi być dokładnie taki jak w Google Console

## ❌ Rozwiązywanie Problemów

### "CORS error"
- Upewnij się, że backend jest uruchomiony na `http://localhost:3001`
- Sprawdź czy nie ma błędów w terminalu backend'u

### "Unauthorized - nie jesteś zalogowany"
- Sprawdź czy okno logowania się otwiera
- Zaloguj się na swoje konto Google
- Zaakceptuj dostęp do Gmaila

### "Brak rachunków"
- Upewnij się, że masz e-maile zawierające "rachunek", "invoice" lub "billing"
- Sprawdź folder Spam
- Aplikacja szuka w ostatnich 10 nieczytanych wiadomościach

## 📝 Notatki

- Aplikacja szuka wiadomości z słowami: `rachunek`, `invoice`, `billing`
- Próbuje wydobyć kwoty z tematu i treści wiadomości
- Datę terminu domyślnie ustawia na 7 dni od dzisiaj
- Każdy rachunek z Gmaila ma ID wiadomości, aby uniknąć duplikatów
