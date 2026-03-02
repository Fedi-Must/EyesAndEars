(() => {
  const STORAGE_KEY = "eae_lang";
  const THEME_STORAGE_KEY = "eae_theme";
  const DEFAULT_LANG = "en";
  const DEFAULT_THEME = "light";
  const SUPPORTED_LANGS = ["en", "fr", "ar"];
  const SUPPORTED_THEMES = ["light", "dark"];
  const RTL_LANGS = new Set(["ar"]);
  const SCRAMBLE_CHARSETS = {
    en: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    fr: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789àâçéèêëîïôùûüÿœ",
    ar: "ابتثجحخدذرزسشصضطظعغفقكلمنهوي٠١٢٣٤٥٦٧٨٩",
  };

  const translations = {
    en: {
      brand: "Eyes & Ears",
      nav_demo: "Demo",
      nav_controls: "Controls",
      nav_features: "Features",
      nav_pricing: "Pricing",
      nav_faq: "FAQ",
      nav_checkout: "Checkout",
      lang_label: "Language",
      theme_toggle_to_dark: "Dark mode",
      theme_toggle_to_light: "Light mode",

      launch_kicker: "EyesAndEars",
      launch_title: "Your invisible on-screen helper.",
      launch_text: "Screenshot any challenge, get an instant answer, and type naturally without app clutter.",
      launch_download: "Instant Download (.exe)",
      launch_unlock: "Unlock Pro Access",
      launch_note: "Free with your own API key, or paid with a code login for hassle-free unlimited usage.",

      terminal_aria: "Install commands for Windows",
      terminal_head_left: "PowerShell",
      terminal_head_right: "Windows",
      terminal_shell_title: "Windows PowerShell",
      terminal_prompt: "PS C:\\WINDOWS\\system32>",
      terminal_command: "winget install EyesAndEars",
      terminal_code: "Windows PowerShell\nPS C:\\WINDOWS\\system32>winget install EyesAndEars",
      copy_winget: "Copy winget command",
      copy_link: "Copy download link",
      copy_success: "Copied",
      copy_failed: "Copy failed",
      copy_toast: "Copied to clipboard",
      terminal_foot: "Install from any Windows PC using one command, or grab the direct .exe link.",
      post_install_title: "After You Download",
      post_install_subtitle: "Watch the interactive first-launch sign-in and indicator setup flow from <code>import os.py</code>.",
      post_terminal_head_left: "Startup",
      post_terminal_head_right: "EyesAndEars.exe",
      post_install_source: "Mirrors the real sign-in and indicator behavior from <code>import os.py</code>.",
      post_install_next: "Next",
      post_install_restart: "Restart demo",
      post_install_replay: "Replay demo",
      post_install_running: "Running...",
      post_ui_title: "Eyes & Ears Sign In",
      post_ui_subtitle: "Private startup authentication",
      post_ui_subscription: "Subscription code mode: Coming soon",
      post_ui_mode_license: "Subscription Code (Coming Soon)",
      post_ui_mode_license_unlocked: "Use Subscription Code",
      post_ui_mode_api: "Use My API Key",
      post_ui_blob_label: "Indicator Blob Size",
      post_ui_blob_very_small: "Very Small",
      post_ui_blob_small: "Small",
      post_ui_blob_medium: "Medium",
      post_ui_blob_large: "Large",
      post_ui_api_label: "Gemini API key",
      post_ui_continue: "Continue",
      post_ui_note: "Stored locally with Windows data protection (DPAPI).",
      post_ui_note_unlock: "Konami sequence entered: subscription mode unlocked for developer testing.",
      post_ui_note_ready: "Continue pressed: API mode active, tray session started, indicator idle in gray.",
      post_real_default_title: "Real startup flow",
      post_real_default_desc: "The walkthrough matches the current app: API key path enabled, subscription mode hidden behind a developer unlock, and internal server endpoint handling.",
      post_real_step_1_title: "Sign-in window opens",
      post_real_step_1_desc: "The current app launches into a styled sign-in window with API mode selected by default.",
      post_real_step_2_title: "Blob size preview",
      post_real_step_2_desc: "Blob size is selectable and previewed before launch; default is Medium.",
      post_real_step_3_title: "API mode path",
      post_real_step_3_desc: "API key mode is available immediately and stores the key with local protection.",
      post_real_step_4_title: "Hidden developer unlock",
      post_real_step_4_desc: "Subscription code mode is intentionally hidden unless the Konami sequence is entered.",
      post_real_step_5_title: "App runs in tray",
      post_real_step_5_desc: "After Continue, tray mode starts and the indicator begins in gray idle state with controls shown.",
      post_step_default_title: "Welcome",
      post_step_default_desc: "You will see both startup paths: license code by email, or your own API key.",
      post_step_1_title: "App opens",
      post_step_1_desc: "The app starts and asks which mode you want.",
      post_step_2_title: "Subscription code path",
      post_step_2_desc: "Pick subscription mode, then enter the code sent by email (name + 6 digits).",
      post_step_3_title: "License session starts",
      post_step_3_desc: "If the code is active, session starts and typing hotkeys are enabled.",
      post_step_4_title: "API key path",
      post_step_4_desc: "Or choose API mode and paste your own Gemini/OpenAI API key.",
      post_step_5_title: "You are ready",
      post_step_5_desc: "Both startup choices are now clear: subscription code or own API key.",

      bridge_aria: "Workflow highlights",
      bridge_scan_title: "Scan Any Problem",
      bridge_scan_text: "Tap one key and EyesAndEars reads context from your screen instantly.",
      bridge_answers_title: "Get Direct Answers",
      bridge_answers_text: "MCQ, coding fixes, and comparison tasks are generated in typing-ready format.",
      bridge_everywhere_title: "Works Everywhere",
      bridge_everywhere_text: "Install with one winget command on Windows machines, or use the direct .exe.",

      demo_title: "Interactive Demo (VS Code Style)",
      demo_subtitle: "Try the app-like flow: <code>0</code> toggles context, <code>1</code> capture/pause/resume, <code>2</code> clears context, and the indicator follows gray/orange/green/blue runtime states.",
      window_title: "VS Code Style Live Demo",
      window_shortcut: "Numpad 0: show/hide context | Numpad 1: capture/pause/resume | Numpad 2: clear",
      explorer_label: "EXPLORER",
      panel_mcq_title: "Multiple choice sample",
      panel_mcq_label: "AI typed answer (single letter)",
      panel_mcq_placeholder: "Press Numpad 1, then mash keys...",
      panel_code_title: "Coding prompt and answer in one editor",
      panel_diff_title: "Spot the difference challenge",
      panel_diff_placeholder: "AI writes what it sees and differences...",
      panel_memory_title: "Context memory example",
      panel_memory_hint: "Press Numpad 2 to clear memory context.",
      hidden_overlay: "Context hidden. Press Numpad 0 to show it again.",
      indicator_idle: "Indicator: idle",
      indicator_processing: "Indicator: processing...",
      indicator_ready: "Indicator: ready",
      indicator_typed_open: "Indicator: typed-answer open",
      indicator_context_visible: "Indicator: context visible",
      indicator_context_hidden: "Indicator: context hidden",
      indicator_context_cleared: "Indicator: context cleared",
      indicator_answer_complete: "Indicator: answer complete",
      indicator_panel_controls_title: "Controls",
      indicator_panel_preview_title: "Latest answer",
      indicator_panel_processing_title: "Processing",
      indicator_panel_ready_title: "Ready",
      indicator_panel_paused_title: "Paused",
      indicator_controls_body: "Numpad 1: Capture / Pause / Resume\nNumpad 0: Toggle Context\nNumpad 2: Clear Context",
      indicator_panel_processing_body: "Analyzing screenshot...",
      indicator_panel_ready_body: "Press any key to type the answer.",
      indicator_panel_paused_body: "Press Numpad 1 to resume typing.",
      indicator_status_idle: "Idle",
      indicator_status_processing: "Processing",
      indicator_status_ready: "Ready",
      indicator_status_paused: "Paused",
      indicator_status_typed_open: "Typed output open",
      indicator_status_context_visible: "Context visible",
      indicator_status_context_hidden: "Context hidden",
      indicator_status_context_cleared: "Context cleared",
      indicator_status_answer_complete: "Answer complete",
      memory_prompt_line: "Current prompt: 'Now give it in uppercase only.'",
      memory_context_available: "Context: available (press Numpad 2 to clear)",
      memory_context_cleared: "Context: cleared",

      feature_invisible_title: "Invisible Helper",
      feature_invisible_text: "Takes a screenshot, detects the problem, and prepares a direct answer for live typing.",
      feature_freepaid_title: "Free or Paid",
      feature_freepaid_text: "Free if you bring your own API key. Paid if you want code/password login and hassle-free unlimited requests.",
      feature_continue_title: "Continue-Code Access",
      feature_continue_text: "Subscription email gives a personal code (name + 6 digits), similar to old game continue codes.",
      hero_checkout: "Go to checkout",
      hero_view_controls: "View controls",

      controls_title: "Controls",
      controls_0_title: "Numpad 0",
      controls_0_text: "Hide or show the on-screen context panel.",
      controls_1_title: "Numpad 1",
      controls_1_text: "Trigger screenshot capture flash and processing state in a single press.",
      controls_2_title: "Numpad 2",
      controls_2_text: "Clear context memory and reset current typed output.",
      controls_typing_title: "Typing keys",
      controls_typing_text: "After processing is ready, mash keys and answer is typed character by character.",
      controls_examples_title: "Examples",
      controls_examples_text: "MCQ, coding fix, spot-difference analysis, and memory/context scenario.",
      compact_summary_text: "Free mode uses your own API key. Pro mode uses a license code with one active session and heartbeat timeout.",

      features_launch_title: "Launch mode choice",
      features_launch_text: "At startup user chooses subscription code mode or own API key mode.",
      features_single_title: "Single active code session",
      features_single_text: "Code mode supports one active session per code with heartbeat timeout handling.",
      features_output_title: "Direct output workflow",
      features_output_text: "No paste dump. Every press emits the next character to keep typing natural and controlled.",

      pricing_title: "Pricing",
      pricing_free_title: "Free Mode",
      pricing_free_text: "Use your own API key. Perfect for testing and personal setup.",
      pricing_pro_title: "Pro Mode",
      pricing_pro_text: "Enter your subscription code/password and everything works hassle-free with unlimited requests.",
      pricing_checkout: "Checkout",

      faq_title: "FAQ",
      faq_code_q: "What does a code look like?",
      faq_code_a: "Example: <code>ALICE930144</code> (name + 6 digits).",
      faq_api_q: "Can I still use my own API key?",
      faq_api_a: "Yes. Free mode is available by choosing API key at startup.",
      faq_numpad_q: "What does Numpad 2 do in the demo?",
      faq_numpad_a: "It clears context memory and resets current output, simulating app context reset behavior.",

      checkout_title: "Checkout (Flouci - Tunisia)",
      checkout_intro: "Enter your name and email to open Flouci payment. Your access code is generated as your name + 6 digits.",
      checkout_name_label: "Name",
      checkout_name_placeholder: "Your name",
      checkout_email_label: "Email",
      checkout_email_placeholder: "you@example.com",
      checkout_submit: "Go to secure checkout",

      account_title: "Account lookup",
      account_intro: "Use the same email and license code from your subscription email.",
      account_email_label: "Email",
      account_email_placeholder: "you@example.com",
      account_license_label: "License code",
      account_license_placeholder: "YOURNAME123456",
      account_submit: "View status",

      checkout_success_title_ok: "Payment confirmed",
      checkout_success_title_pending: "Payment processing",
      checkout_success_desc: "When verification succeeds, your Eyes & Ears continue code (name + 6 digits) is sent by email.",
      checkout_success_help: "If you do not see it, check spam or contact support.",
      checkout_success_account_btn: "Open account page",
    },
    fr: {
      brand: "Eyes & Ears",
      nav_demo: "Démo",
      nav_controls: "Contrôles",
      nav_features: "Fonctionnalités",
      nav_pricing: "Tarifs",
      nav_faq: "FAQ",
      nav_checkout: "Paiement",
      lang_label: "Langue",
      theme_toggle_to_dark: "Mode sombre",
      theme_toggle_to_light: "Mode clair",

      launch_kicker: "EyesAndEars",
      launch_title: "Votre assistant invisible à l’écran.",
      launch_text: "Capturez n'importe quel défi, obtenez une réponse instantanée et tapez naturellement sans encombrer l'écran.",
      launch_download: "Téléchargement instantané (.exe)",
      launch_unlock: "Débloquer l'accès Pro",
      launch_note: "Gratuit avec votre propre clé API, ou payant avec un code d'accès pour une utilisation illimitée sans friction.",

      terminal_aria: "Commandes d'installation pour Windows",
      terminal_head_left: "PowerShell",
      terminal_head_right: "Windows",
      terminal_shell_title: "Windows PowerShell",
      terminal_prompt: "PS C:\\WINDOWS\\system32>",
      terminal_command: "winget install EyesAndEars",
      terminal_code: "Windows PowerShell\nPS C:\\WINDOWS\\system32>winget install EyesAndEars",
      copy_winget: "Copier la commande winget",
      copy_link: "Copier le lien de téléchargement",
      copy_success: "Copié",
      copy_failed: "Échec de copie",
      copy_toast: "Copié dans le presse-papiers",
      terminal_foot: "Installez depuis n'importe quel PC Windows avec une seule commande, ou utilisez le lien direct .exe.",
      post_install_title: "Après le téléchargement",
      post_install_subtitle: "Appuyez sur Suivant pour simuler ce que <code>EyesAndEars.exe</code> affiche au premier lancement.",
      post_terminal_head_left: "Démarrage",
      post_terminal_head_right: "EyesAndEars.exe",
      post_install_source: "Simulation basée sur le vrai prompt de <code>import os.py</code>.",
      post_install_next: "Suivant",
      post_install_restart: "Relancer la démo",
      post_step_default_title: "Bienvenue",
      post_step_default_desc: "Vous verrez les deux modes: code licence par email, ou clé API.",
      post_step_1_title: "Ouverture de l'app",
      post_step_1_desc: "L'application démarre et vous demande le mode.",
      post_step_2_title: "Parcours code licence",
      post_step_2_desc: "Choisissez abonnement puis entrez le code reçu par email.",
      post_step_3_title: "Session active",
      post_step_3_desc: "Si le code est valide, la session démarre.",
      post_step_4_title: "Parcours API",
      post_step_4_desc: "Ou choisissez le mode API et collez votre clé.",
      post_step_5_title: "Prêt",
      post_step_5_desc: "Les deux choix sont clairs: code abonnement ou clé API.",

      bridge_aria: "Points clés du flux",
      bridge_scan_title: "Analyse instantanée",
      bridge_scan_text: "Une seule touche et EyesAndEars lit le contexte de votre écran immédiatement.",
      bridge_answers_title: "Réponses directes",
      bridge_answers_text: "QCM, corrections de code et comparaisons sont générés dans un format prêt à taper.",
      bridge_everywhere_title: "Disponible partout",
      bridge_everywhere_text: "Installez avec une commande winget sur Windows, ou via le .exe direct.",

      demo_title: "Démo interactive (style VS Code)",
      demo_subtitle: "Essayez le flux réel : <code>0</code> masque/affiche le contexte, <code>1</code> capture, <code>2</code> efface le contexte.",
      window_title: "Démo live style VS Code",
      window_shortcut: "Pavé num 0: afficher/masquer le contexte | Pavé num 1: capture | Pavé num 2: effacer",
      explorer_label: "EXPLORATEUR",
      panel_mcq_title: "Exemple de QCM",
      panel_mcq_label: "Réponse IA tapée (une lettre)",
      panel_mcq_placeholder: "Appuyez sur Pavé num 1 puis tapez des touches...",
      panel_code_title: "Prompt et réponse de code dans un seul éditeur",
      panel_diff_title: "Défi de différence",
      panel_diff_placeholder: "L'IA écrit ce qu'elle voit et les différences...",
      panel_memory_title: "Exemple de mémoire de contexte",
      panel_memory_hint: "Appuyez sur Pavé num 2 pour effacer le contexte mémoire.",
      hidden_overlay: "Contexte masqué. Appuyez sur Pavé num 0 pour l'afficher.",
      indicator_idle: "Indicateur : inactif",
      indicator_processing: "Indicateur : traitement...",
      indicator_ready: "Indicateur : prêt",
      indicator_typed_open: "Indicateur : typed-answer ouvert",
      indicator_context_visible: "Indicateur : contexte visible",
      indicator_context_hidden: "Indicateur : contexte masqué",
      indicator_context_cleared: "Indicateur : contexte effacé",
      indicator_answer_complete: "Indicateur : réponse terminée",
      memory_prompt_line: "Prompt actuel : 'Maintenant donne-le en MAJUSCULES uniquement.'",
      memory_context_available: "Contexte : disponible (appuyez sur Pavé num 2 pour effacer)",
      memory_context_cleared: "Contexte : effacé",

      feature_invisible_title: "Assistant invisible",
      feature_invisible_text: "Prend une capture d'écran, détecte le problème et prépare une réponse directe pour la frappe.",
      feature_freepaid_title: "Gratuit ou payant",
      feature_freepaid_text: "Gratuit si vous utilisez votre clé API. Payant si vous voulez un accès code/mot de passe avec requêtes illimitées.",
      feature_continue_title: "Code de continuité",
      feature_continue_text: "L'email d'abonnement envoie un code personnel (nom + 6 chiffres), comme les anciens codes de continuation.",
      hero_checkout: "Aller au paiement",
      hero_view_controls: "Voir les contrôles",

      controls_title: "Contrôles",
      controls_0_title: "Pavé num 0",
      controls_0_text: "Masquer ou afficher le panneau de contexte à l'écran.",
      controls_1_title: "Pavé num 1",
      controls_1_text: "Déclencher la capture + flash + traitement en une seule pression.",
      controls_2_title: "Pavé num 2",
      controls_2_text: "Effacer le contexte mémoire et réinitialiser la sortie.",
      controls_typing_title: "Touches de frappe",
      controls_typing_text: "Une fois le traitement prêt, tapez des touches et la réponse s'écrit caractère par caractère.",
      controls_examples_title: "Exemples",
      controls_examples_text: "QCM, correction de code, analyse des différences et mémoire de contexte.",
      compact_summary_text: "Le mode gratuit utilise votre propre clé API. Le mode Pro utilise un code licence avec une seule session active et expiration heartbeat.",

      features_launch_title: "Choix du mode de lancement",
      features_launch_text: "Au démarrage, l'utilisateur choisit le mode code d'abonnement ou clé API personnelle.",
      features_single_title: "Session unique active",
      features_single_text: "Le mode code applique une seule session active par code avec expiration heartbeat.",
      features_output_title: "Sortie directe",
      features_output_text: "Pas de collage massif : chaque pression émet le caractère suivant pour une frappe naturelle.",

      pricing_title: "Tarifs",
      pricing_free_title: "Mode gratuit",
      pricing_free_text: "Utilisez votre propre clé API. Idéal pour tester et personnaliser.",
      pricing_pro_title: "Mode Pro",
      pricing_pro_text: "Entrez votre code/mot de passe d'abonnement et tout fonctionne sans friction avec requêtes illimitées.",
      pricing_checkout: "Paiement",

      faq_title: "FAQ",
      faq_code_q: "À quoi ressemble un code ?",
      faq_code_a: "Exemple : <code>ALICE930144</code> (nom + 6 chiffres).",
      faq_api_q: "Puis-je toujours utiliser ma propre clé API ?",
      faq_api_a: "Oui. Le mode gratuit est disponible en choisissant la clé API au démarrage.",
      faq_numpad_q: "Que fait Pavé num 2 dans la démo ?",
      faq_numpad_a: "Il efface la mémoire de contexte et réinitialise la sortie actuelle.",

      checkout_title: "Paiement (Flouci - Tunisie)",
      checkout_intro: "Entrez votre nom et votre email pour ouvrir le paiement Flouci. Votre code d'accès est généré sous forme nom + 6 chiffres.",
      checkout_name_label: "Nom",
      checkout_name_placeholder: "Votre nom",
      checkout_email_label: "Email",
      checkout_email_placeholder: "vous@exemple.com",
      checkout_submit: "Aller au paiement sécurisé",

      account_title: "Recherche de compte",
      account_intro: "Utilisez le même email et code de licence reçus par email d'abonnement.",
      account_email_label: "Email",
      account_email_placeholder: "vous@exemple.com",
      account_license_label: "Code de licence",
      account_license_placeholder: "VOTRENOM123456",
      account_submit: "Voir le statut",

      checkout_success_title_ok: "Paiement confirmé",
      checkout_success_title_pending: "Paiement en cours",
      checkout_success_desc: "Quand la vérification réussit, votre code Eyes & Ears (nom + 6 chiffres) est envoyé par email.",
      checkout_success_help: "Si vous ne le voyez pas, vérifiez les spams ou contactez le support.",
      checkout_success_account_btn: "Ouvrir la page du compte",
    },
    ar: {
      brand: "Eyes & Ears",
      nav_demo: "تجربة",
      nav_controls: "التحكم",
      nav_features: "المزايا",
      nav_pricing: "الأسعار",
      nav_faq: "الأسئلة",
      nav_checkout: "الدفع",
      lang_label: "اللغة",
      theme_toggle_to_dark: "الوضع الداكن",
      theme_toggle_to_light: "الوضع الفاتح",

      launch_kicker: "EyesAndEars",
      launch_title: "مساعدك الخفي على الشاشة.",
      launch_text: "التقط أي تحدٍ على الشاشة، واحصل على إجابة فورية، واكتب بشكل طبيعي بدون إزعاج.",
      launch_download: "تنزيل فوري (.exe)",
      launch_unlock: "فتح الوصول الاحترافي",
      launch_note: "مجاني إذا استخدمت مفتاح API الخاص بك، أو مدفوع بكود دخول لتجربة سلسة وطلبات غير محدودة.",

      terminal_aria: "أوامر التثبيت لويندوز",
      terminal_head_left: "PowerShell",
      terminal_head_right: "Windows",
      terminal_shell_title: "Windows PowerShell",
      terminal_prompt: "PS C:\\WINDOWS\\system32>",
      terminal_command: "winget install EyesAndEars",
      terminal_code: "Windows PowerShell\nPS C:\\WINDOWS\\system32>winget install EyesAndEars",
      copy_winget: "نسخ أمر winget",
      copy_link: "نسخ رابط التنزيل",
      copy_success: "تم النسخ",
      copy_failed: "فشل النسخ",
      copy_toast: "تم النسخ إلى الحافظة",
      terminal_foot: "يمكنك التثبيت من أي جهاز ويندوز بأمر واحد، أو استخدام رابط ملف .exe المباشر.",
      post_install_title: "بعد التنزيل",
      post_install_subtitle: "اضغط التالي لمحاكاة ما يظهر في <code>EyesAndEars.exe</code> عند التشغيل الأول.",
      post_terminal_head_left: "بدء التشغيل",
      post_terminal_head_right: "EyesAndEars.exe",
      post_install_source: "يحاكي نافذة البدء الحقيقية من <code>import os.py</code>.",
      post_install_next: "التالي",
      post_install_restart: "إعادة العرض",
      post_step_default_title: "مرحباً",
      post_step_default_desc: "سترى المسارين: كود اشتراك بالإيميل أو مفتاح API.",
      post_step_1_title: "فتح التطبيق",
      post_step_1_desc: "التطبيق يبدأ ويسألك عن وضع التشغيل.",
      post_step_2_title: "مسار كود الاشتراك",
      post_step_2_desc: "اختر وضع الاشتراك ثم أدخل الكود المرسل عبر البريد.",
      post_step_3_title: "بدء الجلسة",
      post_step_3_desc: "إذا كان الكود صالحاً تبدأ الجلسة مباشرة.",
      post_step_4_title: "مسار API",
      post_step_4_desc: "أو اختر وضع API ثم ألصق مفتاحك.",
      post_step_5_title: "أنت جاهز",
      post_step_5_desc: "الخياران واضحان: كود اشتراك أو مفتاح API شخصي.",

      bridge_aria: "مراحل العمل",
      bridge_scan_title: "افحص أي مشكلة",
      bridge_scan_text: "ضغطة واحدة و EyesAndEars يقرأ سياق الشاشة فوراً.",
      bridge_answers_title: "إجابات مباشرة",
      bridge_answers_text: "أسئلة اختيارية، إصلاحات كود، ومقارنات اختلافات بصيغة جاهزة للكتابة.",
      bridge_everywhere_title: "يعمل في كل مكان",
      bridge_everywhere_text: "ثبّت عبر winget على ويندوز أو استخدم ملف .exe المباشر.",

      demo_title: "تجربة تفاعلية (شكل VS Code)",
      demo_subtitle: "جرّب نفس تدفق التطبيق: <code>0</code> إظهار/إخفاء السياق، <code>1</code> التقاط الشاشة، <code>2</code> مسح السياق.",
      window_title: "تجربة مباشرة بأسلوب VS Code",
      window_shortcut: "لوحة الأرقام 0: إظهار/إخفاء السياق | لوحة الأرقام 1: التقاط | لوحة الأرقام 2: مسح",
      explorer_label: "المستكشف",
      panel_mcq_title: "مثال اختيار من متعدد",
      panel_mcq_label: "إجابة الذكاء المكتوبة (حرف واحد)",
      panel_mcq_placeholder: "اضغط لوحة الأرقام 1 ثم اضغط مفاتيح...",
      panel_code_title: "طلب الكود والإجابة في محرر واحد",
      panel_diff_title: "تحدي اكتشاف الاختلاف",
      panel_diff_placeholder: "الذكاء يكتب ما يراه والاختلافات...",
      panel_memory_title: "مثال ذاكرة السياق",
      panel_memory_hint: "اضغط لوحة الأرقام 2 لمسح ذاكرة السياق.",
      hidden_overlay: "تم إخفاء السياق. اضغط لوحة الأرقام 0 لإظهاره مرة أخرى.",
      indicator_idle: "المؤشر: خامل",
      indicator_processing: "المؤشر: جارٍ المعالجة...",
      indicator_ready: "المؤشر: جاهز",
      indicator_typed_open: "المؤشر: فتح ملف typed-answer",
      indicator_context_visible: "المؤشر: السياق ظاهر",
      indicator_context_hidden: "المؤشر: السياق مخفي",
      indicator_context_cleared: "المؤشر: تم مسح السياق",
      indicator_answer_complete: "المؤشر: اكتملت الإجابة",
      memory_prompt_line: "الطلب الحالي: 'أعطني الإجابة الآن بأحرف كبيرة فقط.'",
      memory_context_available: "السياق: متوفر (اضغط لوحة الأرقام 2 للمسح)",
      memory_context_cleared: "السياق: تم مسحه",

      feature_invisible_title: "مساعد غير مرئي",
      feature_invisible_text: "يلتقط الشاشة، يكتشف المشكلة، ويجهز إجابة مباشرة للكتابة.",
      feature_freepaid_title: "مجاني أو مدفوع",
      feature_freepaid_text: "مجاني بمفتاح API الخاص بك. ومدفوع بكود/كلمة مرور لتجربة سهلة وطلبات غير محدودة.",
      feature_continue_title: "وصول بكود متابعة",
      feature_continue_text: "بعد الاشتراك يصلك كود شخصي (الاسم + 6 أرقام) مثل أكواد المتابعة القديمة في الألعاب.",
      hero_checkout: "الذهاب للدفع",
      hero_view_controls: "عرض التحكم",

      controls_title: "التحكم",
      controls_0_title: "لوحة الأرقام 0",
      controls_0_text: "إظهار أو إخفاء لوحة السياق على الشاشة.",
      controls_1_title: "لوحة الأرقام 1",
      controls_1_text: "تشغيل التقاط الشاشة مع وميض وحالة المعالجة بضغطة واحدة.",
      controls_2_title: "لوحة الأرقام 2",
      controls_2_text: "مسح ذاكرة السياق وإعادة ضبط المخرجات.",
      controls_typing_title: "مفاتيح الكتابة",
      controls_typing_text: "بعد أن تصبح المعالجة جاهزة، اضغط المفاتيح وسيتم إدخال الإجابة حرفاً حرفاً.",
      controls_examples_title: "أمثلة",
      controls_examples_text: "اختيار من متعدد، إصلاح كود، تحليل اختلافات، وسيناريو ذاكرة سياق.",
      compact_summary_text: "الوضع المجاني يستخدم مفتاح API الخاص بك. وضع Pro يستخدم كود ترخيص مع جلسة نشطة واحدة وانتهاء heartbeat.",

      features_launch_title: "اختيار وضع التشغيل",
      features_launch_text: "عند بدء التطبيق يختار المستخدم وضع كود الاشتراك أو وضع مفتاح API الخاص به.",
      features_single_title: "جلسة واحدة فعّالة",
      features_single_text: "وضع الكود يسمح بجلسة فعالة واحدة لكل كود مع مهلة heartbeat.",
      features_output_title: "مخرجات مباشرة",
      features_output_text: "بدون لصق عشوائي: كل ضغطة تكتب الحرف التالي بطريقة طبيعية.",

      pricing_title: "الأسعار",
      pricing_free_title: "الوضع المجاني",
      pricing_free_text: "استخدم مفتاح API الخاص بك. مناسب للتجربة والإعداد الشخصي.",
      pricing_pro_title: "الوضع الاحترافي",
      pricing_pro_text: "أدخل كود/كلمة مرور الاشتراك وكل شيء يعمل بسهولة مع طلبات غير محدودة.",
      pricing_checkout: "الدفع",

      faq_title: "الأسئلة الشائعة",
      faq_code_q: "كيف يبدو الكود؟",
      faq_code_a: "مثال: <code>ALICE930144</code> (الاسم + 6 أرقام).",
      faq_api_q: "هل ما زلت أستطيع استخدام مفتاح API الخاص بي؟",
      faq_api_a: "نعم. الوضع المجاني متاح باختيار مفتاح API عند بدء التشغيل.",
      faq_numpad_q: "ماذا يفعل زر لوحة الأرقام 2 في التجربة؟",
      faq_numpad_a: "يمسح ذاكرة السياق ويعيد ضبط المخرجات الحالية.",

      checkout_title: "الدفع (Flouci - تونس)",
      checkout_intro: "أدخل الاسم والبريد لفتح دفع Flouci. سيتم إنشاء كود وصول بصيغة الاسم + 6 أرقام.",
      checkout_name_label: "الاسم",
      checkout_name_placeholder: "اسمك",
      checkout_email_label: "البريد الإلكتروني",
      checkout_email_placeholder: "you@example.com",
      checkout_submit: "الذهاب للدفع الآمن",

      account_title: "البحث عن الحساب",
      account_intro: "استخدم نفس البريد الإلكتروني وكود الترخيص الموجود في رسالة الاشتراك.",
      account_email_label: "البريد الإلكتروني",
      account_email_placeholder: "you@example.com",
      account_license_label: "كود الترخيص",
      account_license_placeholder: "YOURNAME123456",
      account_submit: "عرض الحالة",

      checkout_success_title_ok: "تم تأكيد الدفع",
      checkout_success_title_pending: "الدفع قيد المعالجة",
      checkout_success_desc: "عند نجاح التحقق، سيتم إرسال كود Eyes & Ears (الاسم + 6 أرقام) إلى بريدك.",
      checkout_success_help: "إذا لم تجده، افحص مجلد الرسائل غير المرغوبة أو تواصل مع الدعم.",
      checkout_success_account_btn: "فتح صفحة الحساب",
    },
  };

  const activeAnimations = new WeakMap();
  let currentTheme = DEFAULT_THEME;
  let followSystemTheme = true;
  let themeAnimationTimer = null;

  const normalizeLang = (lang) => {
    const lower = String(lang || "").trim().toLowerCase();
    if (!lower) return DEFAULT_LANG;
    if (SUPPORTED_LANGS.includes(lower)) return lower;
    if (lower.startsWith("fr")) return "fr";
    if (lower.startsWith("ar")) return "ar";
    return "en";
  };

  const normalizeTheme = (theme) => {
    const value = String(theme || "").trim().toLowerCase();
    if (SUPPORTED_THEMES.includes(value)) return value;
    return DEFAULT_THEME;
  };

  const systemTheme = () => {
    if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {
      return "dark";
    }
    return "light";
  };

  const getCurrentLang = () => normalizeLang(document.documentElement.getAttribute("lang") || DEFAULT_LANG);

  const translate = (key, lang) => {
    if (!key) return "";
    const resolvedLang = normalizeLang(lang);
    return (
      translations[resolvedLang]?.[key]
      ?? translations[DEFAULT_LANG]?.[key]
      ?? key
    );
  };

  const randomFromCharset = (charset) => charset[Math.floor(Math.random() * charset.length)];

  const scrambleText = (element, targetText, lang, animate) => {
    const finalText = String(targetText ?? "");
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    const running = activeAnimations.get(element);
    if (running) {
      window.cancelAnimationFrame(running);
      activeAnimations.delete(element);
    }

    if (!animate || reduceMotion || !finalText) {
      element.textContent = finalText;
      return;
    }

    const charset = SCRAMBLE_CHARSETS[normalizeLang(lang)] || SCRAMBLE_CHARSETS.en;
    const duration = Math.max(320, Math.min(1200, finalText.length * 24));
    const start = performance.now();
    const staticChar = /[\s\n\r\t.,!?;:'"(){}\[\]<>|\/\\\-+=_*`~@#$%^&،؛؟]/;

    const frame = (now) => {
      const progress = Math.min(1, (now - start) / duration);
      const revealCount = Math.floor(progress * finalText.length);
      let output = "";
      for (let i = 0; i < finalText.length; i += 1) {
        const char = finalText[i];
        if (i < revealCount || staticChar.test(char)) {
          output += char;
        } else {
          output += randomFromCharset(charset);
        }
      }
      element.textContent = output;
      if (progress < 1) {
        activeAnimations.set(element, window.requestAnimationFrame(frame));
      } else {
        element.textContent = finalText;
        activeAnimations.delete(element);
      }
    };

    activeAnimations.set(element, window.requestAnimationFrame(frame));
  };

  const setDirection = (lang) => {
    const rtl = RTL_LANGS.has(lang);
    document.documentElement.setAttribute("lang", lang);
    document.documentElement.setAttribute("dir", rtl ? "rtl" : "ltr");
    document.body.classList.toggle("rtl", rtl);
    document.body.dataset.lang = lang;
  };

  const applyTranslations = (lang, animate = false) => {
    const resolvedLang = normalizeLang(lang);
    setDirection(resolvedLang);

    document.querySelectorAll("[data-i18n]").forEach((node) => {
      const key = node.getAttribute("data-i18n");
      const value = translate(key, resolvedLang);
      if (node.hasAttribute("data-i18n-no-scramble")) {
        node.textContent = value;
      } else {
        scrambleText(node, value, resolvedLang, animate);
      }
    });

    document.querySelectorAll("[data-i18n-html]").forEach((node) => {
      const key = node.getAttribute("data-i18n-html");
      node.innerHTML = translate(key, resolvedLang);
    });

    document.querySelectorAll("[data-i18n-placeholder]").forEach((node) => {
      const key = node.getAttribute("data-i18n-placeholder");
      node.setAttribute("placeholder", translate(key, resolvedLang));
    });

    document.querySelectorAll("[data-i18n-aria-label]").forEach((node) => {
      const key = node.getAttribute("data-i18n-aria-label");
      node.setAttribute("aria-label", translate(key, resolvedLang));
    });

    document.querySelectorAll("[data-lang-btn]").forEach((node) => {
      const value = String(node.getAttribute("data-lang-btn") || "").toLowerCase();
      node.classList.toggle("active", value === resolvedLang);
      node.setAttribute("aria-pressed", value === resolvedLang ? "true" : "false");
    });

    const toggle = document.getElementById("theme-toggle");
    if (toggle) {
      const nextKey = currentTheme === "dark" ? "theme_toggle_to_light" : "theme_toggle_to_dark";
      const label = translate(nextKey, resolvedLang);
      toggle.setAttribute("aria-label", label);
      toggle.setAttribute("title", label);
    }

    window.dispatchEvent(new CustomEvent("eae:lang-change", { detail: { lang: resolvedLang } }));
  };

  const applyTheme = (theme, options = {}) => {
    const resolvedTheme = normalizeTheme(theme);
    const persist = options.persist !== false;
    const animate = options.animate === true;
    const root = document.body;
    if (!root) return;
    currentTheme = resolvedTheme;
    root.dataset.theme = resolvedTheme;
    document.documentElement.dataset.theme = resolvedTheme;

    if (themeAnimationTimer) {
      window.clearTimeout(themeAnimationTimer);
      themeAnimationTimer = null;
    }
    if (animate) {
      root.classList.add("theme-animating");
      themeAnimationTimer = window.setTimeout(() => {
        root.classList.remove("theme-animating");
        themeAnimationTimer = null;
      }, 980);
    } else {
      root.classList.remove("theme-animating");
    }

    if (persist) {
      try {
        window.localStorage.setItem(THEME_STORAGE_KEY, resolvedTheme);
      } catch {
        // Ignore storage failures in private mode.
      }
      followSystemTheme = false;
    }

    const toggle = document.getElementById("theme-toggle");
    if (toggle) {
      const nextKey = resolvedTheme === "dark" ? "theme_toggle_to_light" : "theme_toggle_to_dark";
      const label = translate(nextKey, getCurrentLang());
      toggle.setAttribute("aria-label", label);
      toggle.setAttribute("title", label);
    }
  };

  const setLang = (lang, options = {}) => {
    const resolvedLang = normalizeLang(lang);
    const animate = options.animate !== false;
    const persist = options.persist !== false;
    if (persist) {
      try {
        window.localStorage.setItem(STORAGE_KEY, resolvedLang);
      } catch {
        // Ignore storage failures in private mode.
      }
    }
    applyTranslations(resolvedLang, animate);
  };

  const init = () => {
    const langButtons = Array.from(document.querySelectorAll("[data-lang-btn]"));
    const themeToggle = document.getElementById("theme-toggle");
    const stored = (() => {
      try {
        return window.localStorage.getItem(STORAGE_KEY);
      } catch {
        return "";
      }
    })();
    const storedTheme = (() => {
      try {
        return window.localStorage.getItem(THEME_STORAGE_KEY);
      } catch {
        return "";
      }
    })();
    const browser = (navigator.languages && navigator.languages[0]) || navigator.language || DEFAULT_LANG;
    const initialLang = normalizeLang(stored || browser || DEFAULT_LANG);
    const initialTheme = normalizeTheme(storedTheme || systemTheme());
    followSystemTheme = !storedTheme;
    applyTheme(initialTheme, { persist: false });

    langButtons.forEach((button) => {
      button.addEventListener("click", () => {
        const next = button.getAttribute("data-lang-btn") || DEFAULT_LANG;
        setLang(next, { animate: true, persist: true });
      });
    });

    if (themeToggle) {
      themeToggle.addEventListener("click", () => {
        const nextTheme = currentTheme === "dark" ? "light" : "dark";
        applyTheme(nextTheme, { persist: true, animate: true });
      });
    }

    if (window.matchMedia) {
      const colorScheme = window.matchMedia("(prefers-color-scheme: dark)");
      const handleSystemTheme = (event) => {
        if (!followSystemTheme) return;
        applyTheme(event.matches ? "dark" : "light", { persist: false });
      };
      if (typeof colorScheme.addEventListener === "function") {
        colorScheme.addEventListener("change", handleSystemTheme);
      } else if (typeof colorScheme.addListener === "function") {
        colorScheme.addListener(handleSystemTheme);
      }
    }

    applyTranslations(initialLang, false);
  };

  window.__eaeI18n = {
    t: (key) => translate(key, getCurrentLang()),
    setLang: (lang) => setLang(lang, { animate: true, persist: true }),
    getLang: () => getCurrentLang(),
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
