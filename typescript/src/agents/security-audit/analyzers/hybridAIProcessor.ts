/**
 * Hybrid AI Processor
 * Uses local models for initial scan/data collection
 * Sanitizes and anonymizes configs before cloud analysis
 * Sends patterns to Vertex AI for advanced analysis
 * Balances privacy with capability
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import {
  LocalModelConfig,
  VertexConfig,
  SanitizationConfig,
  AuditResult,
  SecurityFinding,
  SeverityLevel
} from '../types';
import { DataSanitizer } from '../utils/sanitizer';

const execAsync = promisify(exec);

interface AnalysisRequest {
  type: 'pattern' | 'anomaly' | 'correlation' | 'risk_assessment';
  data: Record<string, unknown>;
  context?: string;
}

interface AnalysisResult {
  insights: string[];
  riskLevel: SeverityLevel;
  recommendations: string[];
  patterns?: DetectedPattern[];
  anomalies?: DetectedAnomaly[];
}

interface DetectedPattern {
  name: string;
  description: string;
  confidence: number;
  indicators: string[];
}

interface DetectedAnomaly {
  type: string;
  severity: SeverityLevel;
  description: string;
  baseline: unknown;
  observed: unknown;
  deviation: number;
}

export class HybridAIProcessor {
  private localConfig: LocalModelConfig;
  private vertexConfig: VertexConfig;
  private sanitizer: DataSanitizer;
  private localModelAvailable: boolean = false;
  private vertexAvailable: boolean = false;

  constructor(
    localConfig?: Partial<LocalModelConfig>,
    vertexConfig?: Partial<VertexConfig>,
    sanitizationConfig?: Partial<SanitizationConfig>
  ) {
    this.localConfig = {
      enabled: localConfig?.enabled ?? true,
      modelPath: localConfig?.modelPath ?? '',
      modelType: localConfig?.modelType ?? 'ollama',
      endpoint: localConfig?.endpoint ?? 'http://localhost:11434',
      capabilities: localConfig?.capabilities ?? ['scan', 'classify']
    };

    this.vertexConfig = {
      enabled: vertexConfig?.enabled ?? true,
      projectId: vertexConfig?.projectId ?? process.env.GOOGLE_CLOUD_PROJECT ?? '',
      location: vertexConfig?.location ?? 'us-central1',
      modelId: vertexConfig?.modelId ?? 'gemini-1.5-pro',
      useForPatternAnalysis: vertexConfig?.useForPatternAnalysis ?? true,
      useForAnomalyDetection: vertexConfig?.useForAnomalyDetection ?? true
    };

    this.sanitizer = new DataSanitizer(sanitizationConfig);
  }

  /**
   * Initialize the processor and check availability of models
   */
  async initialize(): Promise<void> {
    // Check local model availability
    if (this.localConfig.enabled) {
      this.localModelAvailable = await this.checkLocalModel();
    }

    // Check Vertex AI availability
    if (this.vertexConfig.enabled) {
      this.vertexAvailable = await this.checkVertexAI();
    }
  }

  /**
   * Check if local model is available
   */
  private async checkLocalModel(): Promise<boolean> {
    try {
      switch (this.localConfig.modelType) {
        case 'ollama':
          const { stdout } = await execAsync('curl -s http://localhost:11434/api/tags 2>/dev/null || echo "{}"');
          const response = JSON.parse(stdout);
          return response.models && response.models.length > 0;

        case 'llamacpp':
          // Check if llama.cpp server is running
          await execAsync(`curl -s ${this.localConfig.endpoint}/health 2>/dev/null`);
          return true;

        default:
          return false;
      }
    } catch {
      return false;
    }
  }

  /**
   * Check if Vertex AI is available
   */
  private async checkVertexAI(): Promise<boolean> {
    if (!this.vertexConfig.projectId) {
      return false;
    }

    try {
      // Check for Google Cloud authentication
      const { stdout } = await execAsync('gcloud auth application-default print-access-token 2>/dev/null || echo ""');
      return stdout.trim().length > 0;
    } catch {
      return false;
    }
  }

  /**
   * Process audit results with hybrid AI approach
   * 1. Local model for initial classification and scanning
   * 2. Sanitize sensitive data
   * 3. Vertex AI for pattern analysis
   */
  async processAuditResults(results: AuditResult[]): Promise<AnalysisResult> {
    const insights: string[] = [];
    const recommendations: string[] = [];
    const patterns: DetectedPattern[] = [];
    const anomalies: DetectedAnomaly[] = [];

    // Step 1: Local processing - classify and prioritize findings
    if (this.localModelAvailable) {
      const localAnalysis = await this.localClassification(results);
      insights.push(...localAnalysis.insights);
      patterns.push(...(localAnalysis.patterns || []));
    }

    // Step 2: Prepare sanitized data for cloud analysis
    const sanitizedResults = this.sanitizeForCloud(results);

    // Step 3: Cloud analysis for pattern detection and correlation
    if (this.vertexAvailable && this.vertexConfig.useForPatternAnalysis) {
      const cloudAnalysis = await this.vertexPatternAnalysis(sanitizedResults);
      insights.push(...cloudAnalysis.insights);
      patterns.push(...(cloudAnalysis.patterns || []));
      recommendations.push(...cloudAnalysis.recommendations);
    }

    // Step 4: Anomaly detection
    if (this.vertexAvailable && this.vertexConfig.useForAnomalyDetection) {
      const anomalyResult = await this.vertexAnomalyDetection(sanitizedResults);
      anomalies.push(...(anomalyResult.anomalies || []));
    }

    // Step 5: Local risk assessment (keeps sensitive context local)
    const riskLevel = this.calculateOverallRisk(results, patterns, anomalies);

    // Generate combined recommendations
    const finalRecommendations = this.generateRecommendations(
      results,
      patterns,
      anomalies,
      recommendations
    );

    return {
      insights,
      riskLevel,
      recommendations: finalRecommendations,
      patterns,
      anomalies
    };
  }

  /**
   * Local model classification of findings
   */
  private async localClassification(results: AuditResult[]): Promise<AnalysisResult> {
    const insights: string[] = [];
    const patterns: DetectedPattern[] = [];

    if (!this.localModelAvailable) {
      return { insights: [], riskLevel: SeverityLevel.INFO, recommendations: [] };
    }

    try {
      // Prepare a summary for local model
      const summary = this.createFindingsSummary(results);

      // Query local model for classification
      const prompt = `Analyze these security findings and identify patterns:

${summary}

Provide:
1. Key security patterns observed
2. Priority order for remediation
3. Potential attack vectors`;

      const response = await this.queryLocalModel(prompt);

      // Parse response for insights
      if (response) {
        insights.push(...this.parseInsights(response));

        // Detect patterns from response
        const detectedPatterns = this.detectPatternsFromAnalysis(response, results);
        patterns.push(...detectedPatterns);
      }
    } catch (error) {
      insights.push('Local model analysis unavailable');
    }

    return {
      insights,
      riskLevel: SeverityLevel.MEDIUM,
      recommendations: [],
      patterns
    };
  }

  /**
   * Query local model (Ollama/LlamaCpp)
   */
  private async queryLocalModel(prompt: string): Promise<string> {
    try {
      if (this.localConfig.modelType === 'ollama') {
        const { stdout } = await execAsync(`curl -s http://localhost:11434/api/generate -d '${JSON.stringify({
          model: 'llama2',
          prompt,
          stream: false
        })}'`);

        const response = JSON.parse(stdout);
        return response.response || '';
      }

      // Add support for other local models as needed
      return '';
    } catch {
      return '';
    }
  }

  /**
   * Sanitize audit results for cloud processing
   */
  private sanitizeForCloud(results: AuditResult[]): Record<string, unknown> {
    // Extract patterns without sensitive data
    const sanitized = {
      scanTypes: results.map(r => r.scanType),
      findingCounts: results.map(r => ({
        scanType: r.scanType,
        total: r.findings.length,
        bySeverity: this.countBySeverity(r.findings)
      })),
      patterns: this.extractPatternMetadata(results),
      timeline: this.extractTimeline(results),
      categories: this.extractCategories(results)
    };

    // Apply additional sanitization
    const sanitizedData = this.sanitizer.sanitizeObject(sanitized);

    return sanitizedData.data;
  }

  /**
   * Vertex AI pattern analysis
   */
  private async vertexPatternAnalysis(
    sanitizedData: Record<string, unknown>
  ): Promise<AnalysisResult> {
    if (!this.vertexAvailable) {
      return { insights: [], riskLevel: SeverityLevel.INFO, recommendations: [] };
    }

    try {
      const prompt = `Analyze this security audit data for patterns and provide insights:

${JSON.stringify(sanitizedData, null, 2)}

Identify:
1. Attack patterns or chains
2. Configuration weaknesses
3. Compliance gaps
4. Prioritized recommendations

Format as JSON with fields: insights (array), patterns (array with name, description, confidence), recommendations (array)`;

      const response = await this.queryVertexAI(prompt);
      return this.parseVertexResponse(response);
    } catch {
      return { insights: [], riskLevel: SeverityLevel.INFO, recommendations: [] };
    }
  }

  /**
   * Vertex AI anomaly detection
   */
  private async vertexAnomalyDetection(
    sanitizedData: Record<string, unknown>
  ): Promise<AnalysisResult> {
    if (!this.vertexAvailable) {
      return { insights: [], riskLevel: SeverityLevel.INFO, recommendations: [], anomalies: [] };
    }

    try {
      const prompt = `Detect anomalies in this security data:

${JSON.stringify(sanitizedData, null, 2)}

Look for:
1. Unusual patterns compared to baselines
2. Outliers in finding distributions
3. Suspicious timing patterns
4. Correlation anomalies

Format as JSON with fields: anomalies (array with type, severity, description, deviation)`;

      const response = await this.queryVertexAI(prompt);
      return this.parseVertexAnomalyResponse(response);
    } catch {
      return { insights: [], riskLevel: SeverityLevel.INFO, recommendations: [], anomalies: [] };
    }
  }

  /**
   * Query Vertex AI
   */
  private async queryVertexAI(prompt: string): Promise<string> {
    try {
      // Get access token
      const { stdout: token } = await execAsync(
        'gcloud auth application-default print-access-token 2>/dev/null'
      );

      const endpoint = `https://${this.vertexConfig.location}-aiplatform.googleapis.com/v1/projects/${this.vertexConfig.projectId}/locations/${this.vertexConfig.location}/publishers/google/models/${this.vertexConfig.modelId}:generateContent`;

      const payload = {
        contents: [{
          role: 'user',
          parts: [{ text: prompt }]
        }],
        generationConfig: {
          temperature: 0.1,
          maxOutputTokens: 2048
        }
      };

      const { stdout } = await execAsync(`curl -s -X POST "${endpoint}" \
        -H "Authorization: Bearer ${token.trim()}" \
        -H "Content-Type: application/json" \
        -d '${JSON.stringify(payload)}'`);

      const response = JSON.parse(stdout);
      return response.candidates?.[0]?.content?.parts?.[0]?.text || '';
    } catch {
      return '';
    }
  }

  /**
   * Helper methods
   */
  private createFindingsSummary(results: AuditResult[]): string {
    const lines: string[] = [];

    for (const result of results) {
      lines.push(`\n## ${result.scanType} Scan`);
      lines.push(`Total findings: ${result.findings.length}`);
      lines.push(`Critical: ${result.summary.criticalCount}, High: ${result.summary.highCount}`);

      // Add sanitized finding types
      const types = [...new Set(result.findings.map(f => f.type))];
      lines.push(`Finding types: ${types.join(', ')}`);
    }

    return lines.join('\n');
  }

  private countBySeverity(findings: SecurityFinding[]): Record<string, number> {
    return {
      critical: findings.filter(f => f.severity === SeverityLevel.CRITICAL).length,
      high: findings.filter(f => f.severity === SeverityLevel.HIGH).length,
      medium: findings.filter(f => f.severity === SeverityLevel.MEDIUM).length,
      low: findings.filter(f => f.severity === SeverityLevel.LOW).length,
      info: findings.filter(f => f.severity === SeverityLevel.INFO).length
    };
  }

  private extractPatternMetadata(results: AuditResult[]): string[] {
    const patterns: Set<string> = new Set();

    for (const result of results) {
      for (const finding of result.findings) {
        patterns.add(finding.type);
      }
    }

    return Array.from(patterns);
  }

  private extractTimeline(results: AuditResult[]): Record<string, string> {
    const timeline: Record<string, string> = {};

    for (const result of results) {
      timeline[result.scanType] = result.startTime.toISOString();
    }

    return timeline;
  }

  private extractCategories(results: AuditResult[]): Record<string, number> {
    const categories: Record<string, number> = {};

    for (const result of results) {
      for (const finding of result.findings) {
        const category = finding.type.split('_')[0];
        categories[category] = (categories[category] || 0) + 1;
      }
    }

    return categories;
  }

  private parseInsights(response: string): string[] {
    // Extract bullet points or numbered items from response
    const lines = response.split('\n');
    return lines
      .filter(line => line.match(/^[\-\*\d\.]/))
      .map(line => line.replace(/^[\-\*\d\.]\s*/, '').trim())
      .filter(line => line.length > 10);
  }

  private detectPatternsFromAnalysis(
    response: string,
    results: AuditResult[]
  ): DetectedPattern[] {
    const patterns: DetectedPattern[] = [];

    // Detect common attack patterns from findings
    const allFindings = results.flatMap(r => r.findings);

    // Check for brute force pattern
    const bruteForceFindings = allFindings.filter(f =>
      f.type.includes('brute') || f.type.includes('auth_fail')
    );
    if (bruteForceFindings.length >= 5) {
      patterns.push({
        name: 'brute_force_attack',
        description: 'Multiple authentication failures indicating a brute force attack',
        confidence: Math.min(0.95, 0.5 + bruteForceFindings.length * 0.05),
        indicators: bruteForceFindings.slice(0, 3).map(f => f.title)
      });
    }

    // Check for privilege escalation chain
    const privEscFindings = allFindings.filter(f =>
      f.type.includes('privilege') || f.type.includes('sudo') || f.type.includes('root')
    );
    if (privEscFindings.length >= 2) {
      patterns.push({
        name: 'privilege_escalation_attempt',
        description: 'Activities suggesting privilege escalation attempts',
        confidence: Math.min(0.9, 0.4 + privEscFindings.length * 0.1),
        indicators: privEscFindings.slice(0, 3).map(f => f.title)
      });
    }

    // Check for data exfiltration pattern
    const exfilFindings = allFindings.filter(f =>
      f.type.includes('exfil') || f.type.includes('transfer') || f.type.includes('data')
    );
    if (exfilFindings.length >= 1) {
      patterns.push({
        name: 'potential_data_exfiltration',
        description: 'Suspicious data transfer activities detected',
        confidence: Math.min(0.85, 0.3 + exfilFindings.length * 0.15),
        indicators: exfilFindings.slice(0, 3).map(f => f.title)
      });
    }

    return patterns;
  }

  private parseVertexResponse(response: string): AnalysisResult {
    try {
      // Try to parse JSON from response
      const jsonMatch = response.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        return {
          insights: parsed.insights || [],
          riskLevel: SeverityLevel.MEDIUM,
          recommendations: parsed.recommendations || [],
          patterns: parsed.patterns || []
        };
      }
    } catch {
      // Fall back to text parsing
    }

    return {
      insights: this.parseInsights(response),
      riskLevel: SeverityLevel.MEDIUM,
      recommendations: []
    };
  }

  private parseVertexAnomalyResponse(response: string): AnalysisResult {
    try {
      const jsonMatch = response.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        return {
          insights: [],
          riskLevel: SeverityLevel.MEDIUM,
          recommendations: [],
          anomalies: (parsed.anomalies || []).map((a: Record<string, unknown>) => ({
            type: a.type as string,
            severity: this.parseSeverity(a.severity as string),
            description: a.description as string,
            baseline: a.baseline,
            observed: a.observed,
            deviation: a.deviation as number || 0
          }))
        };
      }
    } catch {
      // Fallback
    }

    return { insights: [], riskLevel: SeverityLevel.INFO, recommendations: [], anomalies: [] };
  }

  private parseSeverity(severity: string): SeverityLevel {
    const severityMap: Record<string, SeverityLevel> = {
      critical: SeverityLevel.CRITICAL,
      high: SeverityLevel.HIGH,
      medium: SeverityLevel.MEDIUM,
      low: SeverityLevel.LOW,
      info: SeverityLevel.INFO
    };
    return severityMap[severity?.toLowerCase()] || SeverityLevel.MEDIUM;
  }

  private calculateOverallRisk(
    results: AuditResult[],
    patterns: DetectedPattern[],
    anomalies: DetectedAnomaly[]
  ): SeverityLevel {
    let riskScore = 0;

    // Score from findings
    for (const result of results) {
      riskScore += result.summary.criticalCount * 10;
      riskScore += result.summary.highCount * 7;
      riskScore += result.summary.mediumCount * 4;
      riskScore += result.summary.lowCount * 1;
    }

    // Score from patterns
    for (const pattern of patterns) {
      riskScore += pattern.confidence * 15;
    }

    // Score from anomalies
    for (const anomaly of anomalies) {
      if (anomaly.severity === SeverityLevel.CRITICAL) riskScore += 10;
      else if (anomaly.severity === SeverityLevel.HIGH) riskScore += 7;
      else riskScore += 3;
    }

    if (riskScore >= 50) return SeverityLevel.CRITICAL;
    if (riskScore >= 30) return SeverityLevel.HIGH;
    if (riskScore >= 15) return SeverityLevel.MEDIUM;
    if (riskScore >= 5) return SeverityLevel.LOW;
    return SeverityLevel.INFO;
  }

  private generateRecommendations(
    results: AuditResult[],
    patterns: DetectedPattern[],
    anomalies: DetectedAnomaly[],
    existingRecommendations: string[]
  ): string[] {
    const recommendations = new Set<string>(existingRecommendations);

    // Add recommendations based on patterns
    for (const pattern of patterns) {
      if (pattern.name === 'brute_force_attack') {
        recommendations.add('Implement rate limiting and account lockout policies');
        recommendations.add('Enable MFA for all user accounts');
      }
      if (pattern.name === 'privilege_escalation_attempt') {
        recommendations.add('Review and restrict sudo permissions');
        recommendations.add('Implement least privilege access controls');
      }
      if (pattern.name === 'potential_data_exfiltration') {
        recommendations.add('Implement DLP controls on egress traffic');
        recommendations.add('Monitor and alert on large data transfers');
      }
    }

    // Add recommendations from audit summaries
    for (const result of results) {
      recommendations.add(...result.summary.recommendations);
    }

    return Array.from(recommendations);
  }

  /**
   * Get processor status
   */
  getStatus(): { localAvailable: boolean; vertexAvailable: boolean } {
    return {
      localAvailable: this.localModelAvailable,
      vertexAvailable: this.vertexAvailable
    };
  }
}

export default HybridAIProcessor;
