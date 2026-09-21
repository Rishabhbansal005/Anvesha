import React, { useState } from 'react';
import { 
  BarChart3, 
  CheckCircle2, 
  ShieldAlert, 
  Download, 
  Layers, 
  TrendingUp, 
  Split, 
  Maximize2,
  FileCheck
} from 'lucide-react';

interface PlotItem {
  id: string;
  title: string;
  category: string;
  description: string;
  imageSrc: string;
  keyMetric: string;
  metricLabel: string;
}

const PLOTS: PlotItem[] = [
  {
    id: 'master',
    title: 'Master Forensic Evaluation Dashboard',
    category: 'Publication Composite',
    description: 'Unified 6-panel academic diagnostic poster compiling dataset split, confusion matrix, ROC-AUC curve, PR curve, bimodal score calibration, and top TF-IDF linguistic threat features.',
    imageSrc: '/plots/anvesh_model_evaluation_master_dashboard.png',
    keyMetric: '6 Panels',
    metricLabel: 'Academic Poster (300 DPI)'
  },
  {
    id: 'cm',
    title: 'Confusion Matrix Heatmap',
    category: 'Classification Integrity',
    description: 'Evaluation on 2,669 validation samples showing zero false positives and zero missed threats under strict class balancing.',
    imageSrc: '/plots/01_confusion_matrix.png',
    keyMetric: '0.00%',
    metricLabel: 'False Positive Rate'
  },
  {
    id: 'roc',
    title: 'Receiver Operating Characteristic (ROC)',
    category: 'Discrimination Capacity',
    description: 'ROC curve showing complete separation between benign legitimate emails and malicious phishing threats across varying decision thresholds.',
    imageSrc: '/plots/02_roc_curve.png',
    keyMetric: '1.0000',
    metricLabel: 'Area Under Curve (AUC)'
  },
  {
    id: 'pr',
    title: 'Precision-Recall Tradeoff Curve',
    category: 'Threat Neutralization',
    description: 'Precision-Recall curve validating that high recall coverage is maintained without degrading forensic evidence precision.',
    imageSrc: '/plots/03_precision_recall_curve.png',
    keyMetric: '1.0000',
    metricLabel: 'Average Precision (AP)'
  },
  {
    id: 'prob_dist',
    title: 'Prediction Confidence & Bimodal Separation',
    category: 'Calibration & Ambiguity Control',
    description: 'Density histogram demonstrating that benign samples cluster tightly near 0.00 and phishing threats cluster near 1.00 with clean margin around the 0.50 cutoff.',
    imageSrc: '/plots/04_probability_distribution.png',
    keyMetric: 'Bimodal',
    metricLabel: 'Score Separation'
  },
  {
    id: 'features',
    title: 'Top 20 Indicative Linguistic Threat Features',
    category: 'Model Explainability (XAI)',
    description: 'Logistic Regression log-odds coefficients showing the most statistically significant threat tokens (urgent, verify, account, locked, credentials, suspended).',
    imageSrc: '/plots/05_top_linguistic_features.png',
    keyMetric: '12,000',
    metricLabel: 'TF-IDF Sublinear N-Grams'
  },
  {
    id: 'split',
    title: 'Dataset Split & Partition Architecture',
    category: 'Corpus Governance',
    description: 'Deterministic 70/30 split across Zenodo IEEE 2024, Enron, CEAS, and User Lures, with complete cryptographic isolation of the IWSPA-AP benchmark.',
    imageSrc: '/plots/06_dataset_split_architecture.png',
    keyMetric: '12,833',
    metricLabel: 'Total Unique Samples'
  }
];

export const ModelEvaluationViewer: React.FC = () => {
  const [selectedPlot, setSelectedPlot] = useState<PlotItem>(PLOTS[0]);

  return (
    <div className="space-y-6">
      {/* Top Banner with SIH Metrics */}
      <div className="p-5 rounded-xl bg-[#0F151D] border border-[#25313E] shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#25313E]/60 pb-4 mb-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#10b981]/15 text-[#10b981] border border-[#10b981]/30">
                GOVERNED BENCHMARK
              </span>
              <span className="text-xs font-mono text-[#8996A6]">
                Problem Statement: SIH26106
              </span>
            </div>
            <h3 className="text-base font-bold text-[#E8EDF3] font-mono mt-1 flex items-center gap-2">
              <BarChart3 size={18} className="text-[#5B8DEF]" />
              MODEL 1 FORENSIC EVALUATION & DIAGNOSTIC SUITE
            </h3>
          </div>
          <a
            href={selectedPlot.imageSrc}
            download
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#5B8DEF]/15 hover:bg-[#5B8DEF]/25 text-[#5B8DEF] border border-[#5B8DEF]/40 text-xs font-mono font-semibold transition-colors w-fit cursor-pointer"
          >
            <Download size={13} />
            <span>Download Selected Figure</span>
          </a>
        </div>

        {/* 4 Stat Badges */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="p-3 rounded-lg bg-[#080C12] border border-[#25313E]/60">
            <div className="text-[10px] font-mono text-[#8996A6] uppercase">Validation Accuracy</div>
            <div className="text-lg font-bold font-mono text-[#10b981] mt-0.5">100.0%</div>
            <div className="text-[10px] font-mono text-[#6B7280]">2,669 Samples Evaluated</div>
          </div>
          <div className="p-3 rounded-lg bg-[#080C12] border border-[#25313E]/60">
            <div className="text-[10px] font-mono text-[#8996A6] uppercase">ROC-AUC Score</div>
            <div className="text-lg font-bold font-mono text-[#06b6d4] mt-0.5">1.0000</div>
            <div className="text-[10px] font-mono text-[#6B7280]">Zero Threshold Distortion</div>
          </div>
          <div className="p-3 rounded-lg bg-[#080C12] border border-[#25313E]/60">
            <div className="text-[10px] font-mono text-[#8996A6] uppercase">False Positive Rate</div>
            <div className="text-lg font-bold font-mono text-[#3b82f6] mt-0.5">0.00%</div>
            <div className="text-[10px] font-mono text-[#6B7280]">TN: 1,160 | FP: 0</div>
          </div>
          <div className="p-3 rounded-lg bg-[#080C12] border border-[#25313E]/60">
            <div className="text-[10px] font-mono text-[#8996A6] uppercase">Cryptographic Audit</div>
            <div className="text-lg font-bold font-mono text-[#f59e0b] mt-0.5">SHA-256</div>
            <div className="text-[10px] font-mono text-[#6B7280]">Section 63 BSA 2023</div>
          </div>
        </div>
      </div>

      {/* Main View: Left Menu + Right Active Graph */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Thumbnails List */}
        <div className="lg:col-span-4 space-y-2">
          <div className="text-xs font-mono font-bold uppercase text-[#8996A6] px-1 mb-2">
            Select Evaluation Graph:
          </div>
          {PLOTS.map((plot) => {
            const isSelected = selectedPlot.id === plot.id;
            return (
              <button
                key={plot.id}
                onClick={() => setSelectedPlot(plot)}
                className={`w-full text-left p-3 rounded-xl border transition-all cursor-pointer ${
                  isSelected
                    ? 'bg-[#151D2A] border-[#5B8DEF] shadow-md shadow-[#5B8DEF]/10'
                    : 'bg-[#0F151D] border-[#25313E] hover:border-[#38485B]'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-[#5B8DEF] font-bold">
                    {plot.category}
                  </span>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#080C12] text-[#8996A6] border border-[#25313E]">
                    {plot.keyMetric}
                  </span>
                </div>
                <div className="text-xs font-bold text-[#E8EDF3] font-mono mt-1">
                  {plot.title}
                </div>
                <div className="text-[11px] text-[#8996A6] line-clamp-2 mt-1">
                  {plot.description}
                </div>
              </button>
            );
          })}
        </div>

        {/* Right Active Preview */}
        <div className="lg:col-span-8 space-y-4">
          <div className="p-5 rounded-xl bg-[#0F151D] border border-[#25313E] shadow-sm space-y-4">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="text-xs font-mono text-[#5B8DEF] font-bold uppercase tracking-wider">
                  {selectedPlot.category}
                </div>
                <h4 className="text-sm font-bold text-[#E8EDF3] font-mono mt-0.5">
                  {selectedPlot.title}
                </h4>
                <p className="text-xs text-[#8996A6] mt-1">
                  {selectedPlot.description}
                </p>
              </div>
              <div className="text-right shrink-0">
                <div className="text-sm font-bold font-mono text-[#10b981]">
                  {selectedPlot.keyMetric}
                </div>
                <div className="text-[10px] font-mono text-[#6B7280]">
                  {selectedPlot.metricLabel}
                </div>
              </div>
            </div>

            {/* High-Resolution Plot Image */}
            <div className="relative rounded-lg overflow-hidden border border-[#25313E] bg-[#070A12]">
              <img
                src={selectedPlot.imageSrc}
                alt={selectedPlot.title}
                className="w-full h-auto object-contain max-h-[540px] mx-auto transition-transform hover:scale-[1.01]"
              />
            </div>

            {/* Forensic Admissibility Note */}
            <div className="p-3 rounded-lg bg-[#080C12] border border-[#25313E]/80 flex items-start gap-2.5">
              <FileCheck size={16} className="text-[#10b981] shrink-0 mt-0.5" />
              <div className="text-[11px] text-[#8996A6] leading-relaxed">
                <span className="text-[#E8EDF3] font-semibold">Forensic Admissibility & Non-Attribution Note: </span>
                All metrics derived strictly from non-leaked evaluation partitions under seed <code className="text-[#5B8DEF]">42</code>. Model 1 outputs probabilistic evidence for forensic triage and does not constitute autonomous legal attribution without corroborating RFC 5322 header telemetry.
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
