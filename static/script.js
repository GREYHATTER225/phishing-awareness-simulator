/**
 * Phishing Awareness Tool - Client-side Behavioral Tracking & UI Logic
 * Refactored for modularity, ES6+, descriptive naming, error handling.
 * Handles login form interactions, biometrics collection, validation, UI feedback.
 */

// Common weak passwords for training validation
const COMMON_WEAK_PASSWORDS = [
  '123456', 'password', 'admin', 'qwerty', '123456789', 'password123','11111111'
];

/**
 * Initialize all interactive features on DOM load.
 * Sets up event listeners for flip card, form validation, behavioral tracking.
 */
function initPhishingSimulation() {
  // Safety check first
  if (!document.getElementById('loginForm')) {
    console.warn('Login form not found - skipping phishing sim init');
    return;
  }

  const loginForm = document.getElementById('loginForm');
  const cardInner = document.getElementById('cardInner');
  const toggleBtn = document.querySelector('.toggle__btn');
  const usernameField = document.getElementById("usernameField");
  const passwordField = document.getElementById("passwordField");

  if (!usernameField || !passwordField) {
    console.error('Username or password field missing');
    return;
  }

  // UI interactions
  initFlipCard(toggleBtn, cardInner);
  
  // Behavioral tracking
  const trackingData = initBehavioralTracking(usernameField, passwordField);
  
  // Form handling
  loginForm.onsubmit = (e) => handleFormSubmission(e, loginForm, trackingData, usernameField, passwordField);
}

/**
 * Set up flip card animation for back-side 'signup' tease.
 */
function initFlipCard(toggleBtn, cardInner) {
  if (toggleBtn && cardInner) {
    toggleBtn.addEventListener('click', () => {
      cardInner.classList.toggle('card__inner--flipped');
    });
  }
}

/**
 * Initialize keystroke dynamics and mouse entropy tracking.
 * Returns tracking state object.
 */
function initBehavioralTracking(usernameField, passwordField) {
  const trackingData = {
    sessionStart: Date.now(),
    keystrokeTimes: [],
    mouseMovements: [],
    hintShown: false,
    passwordFocusStart: null
  };

  // Track typing rhythm
  trackKeystrokes(usernameField, trackingData.keystrokeTimes);
  trackKeystrokes(passwordField, trackingData.keystrokeTimes);

  // Mouse pattern entropy
  document.addEventListener('mousemove', (e) => {
    trackingData.mouseMovements.push({
      x: e.clientX,
      y: e.clientY,
      time: Date.now()
    });
  });

  // Security hint trigger
  passwordField.addEventListener('focus', () => {
    trackingData.passwordFocusStart = Date.now();
    if (!trackingData.hintShown) {
      showSecurityHint();
      trackingData.hintShown = true;
    }
  });

  return trackingData;
}

/**
 * Record inter-keystroke timing for human-vs-bot detection.
 */
function trackKeystrokes(inputField, keystrokeTimes) {
  let lastKeyTime = Date.now();
  inputField.addEventListener('keydown', () => {
    const currentTime = Date.now();
    keystrokeTimes.push(currentTime - lastKeyTime);
    lastKeyTime = currentTime;
  });
}

/**
 * Display non-intrusive security reminder hint.
 */
function showSecurityHint() {
  const hintElement = document.createElement('div');
  hintElement.id = 'security-hint';
  hintElement.innerHTML = '🛡️ Never share your real password';
  hintElement.className = 'security__hint';  // Styled in CSS

  const frontCard = document.querySelector('.card__face--front');
  if (frontCard) {
    frontCard.appendChild(hintElement);
  }
}

/**
 * Comprehensive password validation with user feedback.
 */
function validatePassword(password) {
  const trimmedPassword = password.toLowerCase().trim();

  // Check common weak passwords
  if (COMMON_WEAK_PASSWORDS.includes(trimmedPassword)) {
    alert("⚠️ Common password detected - Blocked for training (e.g., '123456', 'password')");
    return false;
  }

  // Length check
  if (password.length < 8) {
    alert("⚠️ Password too short (minimum 8 characters)");
    return false;
  }

  // Complexity check
  if (!/[A-Z]/.test(password) || !/[0-9]/.test(password)) {
    alert("⚠️ Add uppercase letter and number for strength");
    return false;
  }

  return true;
}

/**
 * Main form submission handler with biometrics calculation.
 */
async function handleFormSubmission(event, form, trackingData, usernameField, passwordField) {
  event.preventDefault();

  const password = passwordField.value;
  const username = usernameField.value.trim();

  // Validation first
  if (username.length < 3 || !validatePassword(password)) {
    return false;
  }

  // Compute biometrics
  const timeToSubmit = Date.now() - trackingData.sessionStart;
  const typingDuration = trackingData.passwordFocusStart 
    ? (Date.now() - trackingData.passwordFocusStart) / 1000 
    : 0;
  const avgTypingSpeed = trackingData.keystrokeTimes.length > 0 
    ? trackingData.keystrokeTimes.reduce((sum, time) => sum + time, 0) / trackingData.keystrokeTimes.length 
    : 0;
  const mouseEntropy = calculateMouseEntropy(trackingData.mouseMovements);
  const totalKeystrokes = trackingData.keystrokeTimes.length;
  const riskScore = calculateRiskScore(timeToSubmit, typingDuration, avgTypingSpeed, mouseEntropy);

  // Prepare form data
  const formData = new FormData(form);
  formData.append('timeToSubmit', timeToSubmit);
  formData.append('avgTypingSpeed', avgTypingSpeed);
  formData.append('mouseEntropy', mouseEntropy);
  formData.append('keystrokeCount', totalKeystrokes);
  formData.append('hintsShown', trackingData.hintShown ? '1' : '0');

  // UI feedback
  showLoadingOverlay(riskScore);

  // Submit to server
  try {
    await fetch('/login', { method: 'POST', body: formData });
    setTimeout(() => { window.location.href = '/result'; }, 2500);
  } catch (error) {
    console.error('Submission failed:', error);
    setTimeout(() => { window.location.href = '/result'; }, 2500);
  }
}

/**
 * Calculate mouse movement unpredictability (entropy score).
 */
function calculateMouseEntropy(movements) {
  if (movements.length < 10) return 0;

  const avgDx = movements.reduce((sum, move, i) => {
    if (i === 0) return sum;
    return sum + Math.abs(move.x - movements[i-1].x);
  }, 0) / movements.length;

  const avgDy = movements.reduce((sum, move, i) => {
    if (i === 0) return sum;
    return sum + Math.abs(move.y - movements[i-1].y);
  }, 0) / movements.length;

  return Math.sqrt(avgDx * avgDy);
}

/**
 * Risk score based on behavioral anomalies (lower = more human-like hesitation).
 */
function calculateRiskScore(timeToSubmit, typingDuration, avgTypingSpeed, mouseEntropy) {
  let score = 100;

  if (timeToSubmit < 5000) score -= 30;  // Too fast
  if (typingDuration < 2) score -= 25;   // Copied/pasted
  if (avgTypingSpeed < 200) score -= 20; // Bot-like uniformity
  if (mouseEntropy < 5) score -= 25;     // Scripted movement

  return Math.max(0, score);
}

/**
 * Show realistic MFA-style loading screen with risk feedback.
 */
function showLoadingOverlay(riskScore) {
  const overlay = document.createElement('div');
  overlay.id = 'loading-overlay';
  overlay.className = 'loading__overlay';

  overlay.innerHTML = `
    <div class="loading__title">🔄 Verifying Multi-Factor Authentication...</div>
    <div class="loading__spinner"></div>
    <div class="loading__status" id="riskStatus">Risk Score: ${riskScore}%</div>
  `;

  document.body.appendChild(overlay);

  // Dynamic risk color + pulse
  const statusEl = document.getElementById('riskStatus');
  if (riskScore > 70) {
    statusEl.classList.add('loading__status--high');
  }
}

// Initialize on page load with error protection
document.addEventListener('DOMContentLoaded', () => {
  try {
    initPhishingSimulation();
  } catch (error) {
    console.error('Phishing sim initialization failed:', error);
  }
});

document.addEventListener("DOMContentLoaded", initPhishingSimulation);