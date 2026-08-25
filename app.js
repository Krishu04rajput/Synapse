function togglePassword(id) {
  const input = document.getElementById(id);

  if (!input) return;

  input.type =
    input.type === "password"
      ? "text"
      : "password";
}

function signupUser(event) {
  event.preventDefault();

  const name =
    document.getElementById("signupName").value;

  const username =
    document.getElementById("signupUsername").value;

  const email =
    document.getElementById("signupEmail").value;

  const password =
    document.getElementById("signupPassword").value;

  if (password.length < 8) {
    alert("Password must contain at least 8 characters.");
    return;
  }

  const user = {
    name,
    username,
    email
  };

  localStorage.setItem(
    "synapse_demo_user",
    JSON.stringify(user)
  );

  alert(
    "Account created! Backend authentication will be connected in Phase 2."
  );

  window.location.href = "app.html";
}

function loginUser(event) {
  event.preventDefault();

  const identity =
    document.getElementById("loginIdentity").value;

  const password =
    document.getElementById("loginPassword").value;

  if (!identity || !password) {
    alert("Please enter your login details.");
    return;
  }

  alert(
    "Demo login successful. Real authentication will be connected in Phase 2."
  );

  window.location.href = "app.html";
}

function showNotification() {
  alert("No new notifications.");
}

function openSettings() {
  alert("Settings interface will be expanded in Phase 2.");
}

function openProfile() {
  alert("Profile interface will be expanded in Phase 2.");
}
