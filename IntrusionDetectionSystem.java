package com.codealpha.nids;



	import java.io.FileWriter;
	import java.io.IOException;
	import java.io.PrintWriter;
	import java.time.LocalDateTime;
	import java.time.format.DateTimeFormatter;
	import java.util.ArrayList;
	import java.util.List;
	import java.util.regex.Pattern;

	/**
	 * Task 4: Network Intrusion Detection System (NIDS) Simulation
	 * Internship: CodeAlpha Cybersecurity
	 */
	public class IntrusionDetectionSystem {

	    // NIDS Rule Representation
	    static class Rule {
	        String ruleId;
	        String attackType;
	        Pattern pattern;
	        String severity;

	        public Rule(String ruleId, String attackType, String regex, String severity) {
	            this.ruleId = ruleId;
	            this.attackType = attackType;
	            this.pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
	            this.severity = severity;
	        }
	    }

	    // Simulated Network Packet
	    static class Packet {
	        String sourceIp;
	        String destinationIp;
	        int destinationPort;
	        String payload;

	        public Packet(String sourceIp, String destinationIp, int destinationPort, String payload) {
	            this.sourceIp = sourceIp;
	            this.destinationIp = destinationIp;
	            this.destinationPort = destinationPort;
	            this.payload = payload;
	        }
	    }

	    private static final List<Rule> detectionRules = new ArrayList<>();
	    private static final String LOG_FILE = "nids_alerts.log";

	    public static void main(String[] args) {
	        System.out.println("==================================================");
	        System.out.println("   CodeAlpha Network Intrusion Detection System   ");
	        System.out.println("==================================================\n");

	        // 1. Initialize Rule Base (Configuring Detection Rules)
	        loadRules();

	        // 2. Simulate Incoming Network Packets (Continuous Monitoring)
	        List<Packet> networkTraffic = generateTrafficSample();

	        // 3. Inspect Packets & Trigger Response Mechanisms
	        for (Packet packet : networkTraffic) {
	            inspectPacket(packet);
	        }

	        System.out.println("\n[+] Traffic inspection completed.");
	        System.out.println("[+] Security alerts logged to: " + LOG_FILE);
	    }

	    private static void loadRules() {
	        // Detection Rule Set
	        detectionRules.add(new Rule("RULE-101", "SQL Injection Threat", ".*(UNION\\s+SELECT|DROP\\s+TABLE|'\\s*OR\\s*'1'='1).*", "CRITICAL"));
	        detectionRules.add(new Rule("RULE-102", "Port Scanning Activity", ".*(NMAP|MASSCAN|XMAS\\s+SCAN).*", "HIGH"));
	        detectionRules.add(new Rule("RULE-103", "Directory Traversal", ".*(\\.\\./\\.\\./|/etc/passwd).*", "HIGH"));
	        detectionRules.add(new Rule("RULE-104", "SYN Flood / DoS Attempt", ".*(SYN_FLOOD_PAYLOAD|PACKET_BURST).*", "CRITICAL"));
	        
	        System.out.println("[*] Loaded " + detectionRules.size() + " NIDS detection rules successfully.");
	    }

	    private static void inspectPacket(Packet packet) {
	        for (Rule rule : detectionRules) {
	            if (rule.pattern.matcher(packet.payload).matches()) {
	                triggerAlert(rule, packet);
	            }
	        }
	    }

	    private static void triggerAlert(Rule rule, Packet packet) {
	        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
	        String alertMessage = String.format("[%s] ALERT [%s] [%s] - Source: %s -> Dest: %s:%d | Payload: \"%s\"",
	                timestamp, rule.severity, rule.attackType, packet.sourceIp, packet.destinationIp, packet.destinationPort, packet.payload);

	        // Response Mechanism 1: Real-time Console Warning
	        System.err.println(alertMessage);

	        // Response Mechanism 2: Automated Security Log Recording
	        logToFile(alertMessage);
	    }

	    private static void logToFile(String logEntry) {
	        try (PrintWriter out = new PrintWriter(new FileWriter(LOG_FILE, true))) {
	            out.println(logEntry);
	        } catch (IOException e) {
	            System.out.println("Error writing to log file: " + e.getMessage());
	        }
	    }

	    private static List<Packet> generateTrafficSample() {
	        List<Packet> traffic = new ArrayList<>();
	        
	        // Normal Traffic
	        traffic.add(new Packet("192.168.1.10", "192.168.1.1", 80, "GET /index.html HTTP/1.1"));
	        traffic.add(new Packet("192.168.1.15", "192.168.1.1", 443, "GET /login.jsp HTTP/1.1"));
	        
	        // Malicious Traffic (Triggers Rules)
	        traffic.add(new Packet("10.0.0.45", "192.168.1.1", 80, "GET /products.php?id=1 UNION SELECT * FROM users HTTP/1.1"));
	        traffic.add(new Packet("172.16.0.8", "192.168.1.1", 80, "GET /../../etc/passwd HTTP/1.1"));
	        traffic.add(new Packet("10.0.0.99", "192.168.1.1", 443, "User-Agent: NMAP Scripting Engine"));
	        
	        return traffic;
	    }
	}

