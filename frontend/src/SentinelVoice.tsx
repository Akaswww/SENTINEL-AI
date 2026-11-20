
import { useEffect, useRef, useState } from "react";

type SpeechResultEvent = {
  results: ArrayLike<ArrayLike<{ transcript: string }>>;
};

type SpeechRecognitionLike = {
  lang: string;
  continuous: boolean;
  interimResults: boolean;
  onresult: ((event: SpeechResultEvent) => void) | null;
  onerror: ((event: { error: string }) => void) | null;
  onend: (() => void) | null;
  start: () => void;
  stop: () => void;
};

type SpeechWindow = Window & {
  SpeechRecognition?: new () => SpeechRecognitionLike;
  webkitSpeechRecognition?: new () => SpeechRecognitionLike;
};

type ChatResponse = {
  assistant: string;
  answer: string;
  mode: string;
};

export default function SentinelVoice() {
  const [authenticated, setAuthenticated] = useState(false);
  const [checkingSession, setCheckingSession] = useState(true);
  const [password, setPassword] = useState("");
  const [loginLoading, setLoginLoading] = useState(false);

  const [listening, setListening] = useState(false);
  const [thinking, setThinking] = useState(false);
  const [speaking, setSpeaking] = useState(false);

  const [lastQuestion, setLastQuestion] = useState("");
  const [lastAnswer, setLastAnswer] = useState("");
  const [error, setError] = useState("");

  // Voice settings
  const [availableVoices, setAvailableVoices] =
    useState<SpeechSynthesisVoice[]>([]);
  const [selectedVoice, setSelectedVoice] = useState("");
  const [voiceRate, setVoiceRate] = useState(0.92);
  const [voicePitch, setVoicePitch] = useState(0.85);

  const recognitionRef = useRef<SpeechRecognitionLike | null>(null);
  const utteranceRef = useRef<SpeechSynthesisUtterance | null>(null);
  const requestControllerRef = useRef<AbortController | null>(null);
  const thinkingRef = useRef(false);

  // Load available voices
  useEffect(() => {
    if (!("speechSynthesis" in window)) return;

    function loadVoices() {
      const voices = window.speechSynthesis.getVoices();
      setAvailableVoices(voices);

      setSelectedVoice((current) => {
        if (current && voices.some((v) => v.voiceURI === current)) {
          return current;
        }

        const preferred =
          voices.find(
            (v) =>
              v.lang.toLowerCase() === "en-gb" &&
              /daniel|oliver/i.test(v.name)
          ) ||
          voices.find(
            (v) => v.lang.toLowerCase() === "en-gb"
          ) ||
          voices.find(
            (v) => v.lang.toLowerCase().startsWith("en")
          );

        return preferred?.voiceURI ?? "";
      });
    }

    loadVoices();

    window.speechSynthesis.addEventListener(
      "voiceschanged",
      loadVoices
    );

    return () => {
      window.speechSynthesis.removeEventListener(
        "voiceschanged",
        loadVoices
      );
    };
  }, []);

  // Check dashboard session
  useEffect(() => {
    let active = true;

    async function checkSession() {
      try {
        const response = await fetch("/api/dashboard/session", {
          credentials: "same-origin",
        });

        if (active) setAuthenticated(response.ok);
      } catch {
        if (active) setAuthenticated(false);
      } finally {
        if (active) setCheckingSession(false);
      }
    }

    void checkSession();

    return () => {
      active = false;
      requestControllerRef.current?.abort();
      recognitionRef.current?.stop();

      if ("speechSynthesis" in window) {
        window.speechSynthesis.cancel();
      }
    };
  }, []);

  async function login() {
    if (!password.trim() || loginLoading) return;

    setLoginLoading(true);
    setError("");

    try {
      const response = await fetch("/api/dashboard/login", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ password }),
      });

      if (!response.ok) {
        throw new Error(
          response.status === 401
            ? "Incorrect dashboard password."
            : `Login failed: HTTP ${response.status}`
        );
      }

      setAuthenticated(true);
      setPassword("");
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Login failed."
      );
    } finally {
      setLoginLoading(false);
    }
  }

  function stopSpeaking() {
    if ("speechSynthesis" in window) {
      window.speechSynthesis.cancel();
    }

    utteranceRef.current = null;
    setSpeaking(false);
  }

  function speak(text: string) {
    if (!("speechSynthesis" in window)) {
      setError("Speech synthesis is unavailable.");
      return;
    }

    stopSpeaking();

    const spokenText = text
      .replace(/```[\s\S]*?```/g, " Code example omitted. ")
      .replace(/[*#`_]/g, "")
      .replace(/\n+/g, ". ")
      .trim()
      .slice(0, 3000);

    if (!spokenText) return;

    const utterance = new SpeechSynthesisUtterance(spokenText);

    const preferredVoice = window.speechSynthesis
      .getVoices()
      .find((voice) => voice.voiceURI === selectedVoice);

    if (preferredVoice) {
      utterance.voice = preferredVoice;
    }

    utterance.lang = preferredVoice?.lang || "en-GB";
    utterance.rate = voiceRate;
    utterance.pitch = voicePitch;
    utterance.volume = 1;

    utterance.onstart = () => {
      setSpeaking(true);
    };

    utterance.onend = () => {
      setSpeaking(false);
      utteranceRef.current = null;
    };

    utterance.onerror = (event) => {
      setSpeaking(false);
      utteranceRef.current = null;

      if (
        event.error !== "canceled" &&
        event.error !== "interrupted"
      ) {
        setError(`Voice playback failed: ${event.error}`);
      }
    };

    utteranceRef.current = utterance;
    window.speechSynthesis.speak(utterance);
  }

  async function askSentinel(question: string) {
    const cleanQuestion = question.trim();

    if (!cleanQuestion || thinkingRef.current) return;

    thinkingRef.current = true;
    setThinking(true);
    setLastQuestion(cleanQuestion);
    setLastAnswer("");
    setError("");

    const controller = new AbortController();
    requestControllerRef.current = controller;

    try {
      const response = await fetch("/api/dashboard/chat", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ question: cleanQuestion }),
        signal: controller.signal,
      });

      if (response.status === 401) {
        setAuthenticated(false);
        throw new Error(
          "Dashboard session expired. Please log in again."
        );
      }

      if (!response.ok) {
        const details = await response.text();

        console.error(
          "Sentinel API error:",
          response.status,
          details
        );

        throw new Error(
          `Sentinel API error: ${response.status}`
        );
      }

      const data: ChatResponse = await response.json();

      if (!data.answer?.trim()) {
        throw new Error("Sentinel returned an empty answer.");
      }

      setLastAnswer(data.answer);
      speak(data.answer);
    } catch (err) {
      if (!controller.signal.aborted) {
        setError(
          err instanceof Error
            ? err.message
            : "Unable to contact Sentinel."
        );
      }
    } finally {
      thinkingRef.current = false;
      setThinking(false);

      if (requestControllerRef.current === controller) {
        requestControllerRef.current = null;
      }
    }
  }

  function startListening() {
    if (!authenticated || listening || thinkingRef.current) return;

    const speechWindow = window as SpeechWindow;

    const Recognition =
      speechWindow.SpeechRecognition ||
      speechWindow.webkitSpeechRecognition;

    if (!Recognition) {
      setError(
        "Speech recognition is unavailable in this browser."
      );
      return;
    }

    stopSpeaking();
    setError("");

    const recognition = new Recognition();

    recognition.lang = "en-IN";
    recognition.continuous = false;
    recognition.interimResults = false;

    recognition.onresult = (event) => {
      const transcript =
        event.results[0]?.[0]?.transcript?.trim() || "";

      setListening(false);

      if (transcript) {
        void askSentinel(transcript);
      } else {
        setError("No speech was recognized.");
      }
    };

    recognition.onerror = (event) => {
      setListening(false);
      setError(
        `Microphone recognition failed: ${event.error}`
      );
    };

    recognition.onend = () => {
      setListening(false);
      recognitionRef.current = null;
    };

    recognitionRef.current = recognition;

    try {
      recognition.start();
      setListening(true);
    } catch {
      setListening(false);
      setError("Could not start microphone recognition.");
    }
  }

  function stopListening() {
    recognitionRef.current?.stop();
    setListening(false);
  }

  function testVoice() {
    setError("");
    speak(
      "Good evening. Sentinel is online. All monitoring systems are ready for inspection."
    );
  }

  if (checkingSession) {
    return (
      <section className="voice-assistant">
        <h2>SENTINEL AI</h2>
        <p>Checking secure session...</p>
      </section>
    );
  }

  if (!authenticated) {
    return (
      <section className="voice-assistant">
        <h2>SENTINEL AI</h2>
        <p>Secure Voice Assistant</p>

        <div className="voice-orb">
          <span>◉</span>
        </div>

        <h3>Authentication Required</h3>

        <form
          onSubmit={(event) => {
            event.preventDefault();
            void login();
          }}
        >
          <input
            type="password"
            className="search-input"
            placeholder="Dashboard password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="current-password"
            required
          />

          <button
            type="submit"
            className="voice-button"
            disabled={loginLoading || !password.trim()}
          >
            {loginLoading
              ? "Authenticating..."
              : "Activate Sentinel"}
          </button>
        </form>

        {error && <p className="error">{error}</p>}
      </section>
    );
  }

  return (
    <section className="voice-assistant">
      <h2>SENTINEL AI</h2>
      <p>Voice-Controlled Cybersecurity Assistant</p>

      <div
        className={`voice-orb ${
          listening
            ? "listening"
            : thinking
            ? "thinking"
            : speaking
            ? "speaking"
            : ""
        }`}
      >
        <span>◉</span>
      </div>

      <h3>
        {listening
          ? "Listening..."
          : thinking
          ? "Analyzing security data..."
          : speaking
          ? "Speaking..."
          : "Sentinel is ready"}
      </h3>

      <div className="voice-settings">
        <label htmlFor="sentinel-voice">
          Sentinel Voice
        </label>

        <select
          id="sentinel-voice"
          value={selectedVoice}
          onChange={(event) =>
            setSelectedVoice(event.target.value)
          }
        >
          {availableVoices.length === 0 && (
            <option value="">Default system voice</option>
          )}

          {availableVoices.map((voice) => (
            <option
              key={voice.voiceURI}
              value={voice.voiceURI}
            >
              {voice.name} ({voice.lang})
            </option>
          ))}
        </select>

        <label htmlFor="sentinel-rate">
          Speaking Speed: {voiceRate.toFixed(2)}x
        </label>
        <input
          id="sentinel-rate"
          type="range"
          min="0.7"
          max="1.2"
          step="0.05"
          value={voiceRate}
          onChange={(event) =>
            setVoiceRate(Number(event.target.value))
          }
        />

        <label htmlFor="sentinel-pitch">
          Pitch: {voicePitch.toFixed(2)}
        </label>
        <input
          id="sentinel-pitch"
          type="range"
          min="0.6"
          max="1.2"
          step="0.05"
          value={voicePitch}
          onChange={(event) =>
            setVoicePitch(Number(event.target.value))
          }
        />
      </div>

      <button
        className="voice-button"
        onClick={startListening}
        disabled={listening || thinking}
      >
        {listening ? "Listening..." : "Speak to Sentinel"}
      </button>

      {listening && (
        <button
          className="voice-stop"
          onClick={stopListening}
        >
          Stop Listening
        </button>
      )}

      {speaking && (
        <button
          className="voice-stop"
          onClick={stopSpeaking}
        >
          Stop Speaking
        </button>
      )}

      <button
        className="voice-button"
        onClick={testVoice}
        disabled={listening || thinking}
      >
        Test Voice
      </button>

      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}

      {lastQuestion && (
        <div className="voice-transcript">
          <strong>You:</strong> {lastQuestion}
        </div>
      )}

      {lastAnswer && (
        <div className="voice-transcript">
          <strong>Sentinel:</strong> {lastAnswer}
        </div>
      )}
    </section>
  );
}
