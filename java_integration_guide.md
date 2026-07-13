# Social URL Status Checker - Java & UI Integration Guide

This guide details how to integrate the upgraded **Social URL Status Checker (v5.0)** microservice into your Java application. It covers HTTP API integration, building a native Java GUI (Swing), and embedding the Web UI directly inside a Java desktop application (JavaFX WebView).

---

## 1. API Contract for Java (v5.0)

### Endpoint
*   **Method**: `POST`
*   **URL**: `http://localhost:8000/api/check/json`
*   **Header**: `Content-Type: application/json`

### JSON Request Payload
```json
{
  "urls": [
    "https://t.me/durov",
    "https://apkcombo.com/adani-my-world/com.ambuja.tse/",
    "https://www.linkedin.com/in/williamhgates/"
  ]
}
```

### JSON Response Payload (v5.0 Additions Included)
```json
{
  "results": [
    {
      "url": "https://t.me/durov",
      "platform": "telegram",
      "status": "active",
      "reason": "Telegram profile is active (Pavel Durov)",
      "http_code": 200,
      "confidence": 45,
      "signals": ["dns_resolved", "http_200", "redirect_consistent"],
      "metadata": {
        "total_latency_ms": 600.9
      }
    },
    {
      "url": "https://www.linkedin.com/in/williamhgates/",
      "platform": "linkedin",
      "status": "uncertain",
      "reason": "LinkedIn blocked all bot UAs. Cookies required.",
      "http_code": 403,
      "confidence": 25,
      "signals": ["dns_resolved", "redirect_consistent", "-bot_blocked"],
      "metadata": {
        "total_latency_ms": 1534.2,
        "error_type": "BOT_BLOCK"
      }
    }
  ]
}
```
*Note: Possible `status` values are: `"active"`, `"taken_down"`, `"uncertain"`, `"error"`.*

---

## 2. Option A: Embedding the Web UI in Java (JavaFX WebView)

Since the Python backend now hosts the full web frontend at `http://localhost:8000/`, you can embed this responsive interface directly inside a Java desktop application using **JavaFX WebView**.

### JavaFX Implementation Code

```java
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.layout.BorderPane;
import javafx.scene.web.WebEngine;
import javafx.scene.web.WebView;
import javafx.stage.Stage;

public class EmbeddedValidatorApp extends Application {
    private static final String APP_URL = "http://localhost:8000/";

    @Override
    public void start(Stage stage) {
        stage.setTitle("CYFIRMA Takedown Validator (Embedded)");

        WebView webView = new WebView();
        WebEngine webEngine = webView.getEngine();
        
        // Load the FastAPI-hosted frontend
        webEngine.load(APP_URL);

        BorderPane root = new BorderPane(webView);
        Scene scene = new Scene(root, 1280, 800);

        stage.setScene(scene);
        stage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
```

---

## 3. Option B: Building a Native Java UI (Java Swing Table)

If you prefer a native Java desktop experience, you can build a Java Swing application with a table that updates in real-time by querying the FastAPI endpoint.

### Dependencies
Make sure to include a JSON library like **Gson** or **Jackson** in your project dependencies.

### Swing Implementation Code

```java
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.regex.Pattern;

public class NativeValidatorSwing extends JFrame {
    private JTextArea urlTextArea;
    private JButton checkButton;
    private JTable resultsTable;
    private DefaultTableModel tableModel;

    private static final String API_URL = "http://localhost:8000/api/check/json";

    public NativeValidatorSwing() {
        setTitle("CYFIRMA Takedown Validator (Native)");
        setSize(900, 600);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout(10, 10));

        // ── Input Panel ──
        JPanel inputPanel = new JPanel(new BorderLayout(5, 5));
        inputPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        urlTextArea = new JTextArea(6, 40);
        urlTextArea.setToolTipText("Paste URLs here, one per line...");
        urlTextArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JScrollPane textScrollPane = new JScrollPane(urlTextArea);
        
        checkButton = new JButton("Run Validation");
        checkButton.setBackground(new Color(147, 51, 234)); // Purple Cyber color
        checkButton.setForeground(Color.WHITE);
        checkButton.setFocusPainted(false);
        checkButton.setFont(new Font("SansSerif", Font.BOLD, 13));
        
        inputPanel.add(new JLabel("Paste URLs to check (one per line):"), BorderLayout.NORTH);
        inputPanel.add(textScrollPane, BorderLayout.CENTER);
        inputPanel.add(checkButton, BorderLayout.SOUTH);

        // ── Results Table ──
        String[] columns = {"#", "URL", "Platform", "Status", "Confidence", "Reason", "HTTP"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };
        resultsTable = new JTable(tableModel);
        resultsTable.setFillsViewportHeight(true);
        resultsTable.setRowHeight(25);
        resultsTable.getColumnModel().getColumn(0).setMaxWidth(40);
        resultsTable.getColumnModel().getColumn(4).setMaxWidth(80);
        resultsTable.getColumnModel().getColumn(6).setMaxWidth(60);
        JScrollPane tableScrollPane = new JScrollPane(resultsTable);

        // Add to main frame
        add(inputPanel, BorderLayout.NORTH);
        add(tableScrollPane, BorderLayout.CENTER);

        // ── Button Action ──
        checkButton.addActionListener(e -> runValidation());
    }

    private void runValidation() {
        String rawText = urlTextArea.getText().trim();
        if (rawText.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter some URLs.", "Warning", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Split URLs
        String[] rawUrls = rawText.split("\\R");
        StringBuilder jsonBuilder = new StringBuilder("{\"urls\": [");
        for (int i = 0; i < rawUrls.length; i++) {
            String u = rawUrls[i].trim().replace("\"", "\\\"");
            if (u.isEmpty()) continue;
            jsonBuilder.append("\"").append(u).append("\"");
            if (i < rawUrls.length - 1) jsonBuilder.append(",");
        }
        jsonBuilder.append("]}");

        // Disable input
        checkButton.setEnabled(false);
        checkButton.setText("Checking...");
        tableModel.setRowCount(0);

        // Run HTTP request in a background thread to prevent UI freezing
        new Thread(() -> {
            try {
                HttpClient client = HttpClient.newBuilder()
                        .connectTimeout(Duration.ofSeconds(10))
                        .build();

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(API_URL))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(jsonBuilder.toString()))
                        .timeout(Duration.ofMinutes(2))
                        .build();

                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() == 200) {
                    // Update UI on Event Dispatch Thread
                    SwingUtilities.invokeLater(() -> parseAndPopulate(response.body()));
                } else {
                    SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(this, 
                            "API Error: HTTP " + response.statusCode(), "Error", JOptionPane.ERROR_MESSAGE));
                }
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(this, 
                        "Failed to connect: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE));
            } finally {
                SwingUtilities.invokeLater(() -> {
                    checkButton.setEnabled(true);
                    checkButton.setText("Run Validation");
                });
            }
        }).start();
    }

    private void parseAndPopulate(String responseJson) {
        // Simple manual regex parsing if Gson/Jackson are not present, for demo:
        // (Production apps should use ObjectMapper/Gson parsing)
        Pattern itemPattern = Pattern.compile("\\{\\s*\"url\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*\"platform\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*\"status\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*\"reason\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*\"http_code\"\\s*:\\s*([^,\\}]+)\\s*(?:,\\s*\"confidence\"\\s*:\\s*(\\d+))?");
        var matcher = itemPattern.matcher(responseJson);
        int idx = 1;
        while (matcher.find()) {
            String url = matcher.group(1);
            String platform = matcher.group(2);
            String status = matcher.group(3).toUpperCase();
            String reason = matcher.group(4);
            String httpCode = matcher.group(5).trim().replace("null", "N/A");
            String confidence = matcher.group(6) != null ? matcher.group(6) + "%" : "N/A";

            tableModel.addRow(new Object[]{idx++, url, platform, status, confidence, reason, httpCode});
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new NativeValidatorSwing().setVisible(true));
    }
}
```

---

## 4. Summary of Integration Routes

1. **Option A (JavaFX WebView)** is the **fastest and most feature-complete** option because it embeds the clean cyber-themed web frontend directly into Java.
2. **Option B (Swing / Native Component)** is the best if you want the tool to blend seamlessly with a pre-existing native Java desktop client.
