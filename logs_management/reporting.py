import logging
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import os
from io import BytesIO
import base64

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self, db_logger):
        self.db_logger = db_logger
        plt.style.use('dark_background')
    
    def generate_report(self, output_path: str, hours: int = 24, 
                       format: str = 'pdf') -> bool:
        try:
            start_time = datetime.now() - timedelta(hours=hours)
            
            threats = self.db_logger.get_threat_events(start_time=start_time, limit=10000)
            stats = self.db_logger.get_statistics(hours=hours)
            
            if format == 'csv':
                self._generate_csv_report(threats, output_path)
            elif format == 'pdf':
                self._generate_pdf_report(threats, stats, output_path, hours)
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            logger.info(f"Report generated: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return False
    
    def _generate_csv_report(self, threats: List[Dict], output_path: str):
        if not threats:
            df = pd.DataFrame()
        else:
            df = pd.DataFrame(threats)
            
            columns_to_keep = ['timestamp', 'type', 'severity', 'score',
                             'source_ip', 'destination_ip', 'port', 'protocol',
                             'url', 'process_name']
            
            available_columns = [col for col in columns_to_keep if col in df.columns]
            df = df[available_columns]
        
        df.to_csv(output_path, index=False)
    
    def _generate_pdf_report(self, threats: List[Dict], stats: Dict, 
                           output_path: str, hours: int):
        from matplotlib.backends.backend_pdf import PdfPages
        
        with PdfPages(output_path) as pdf:
            # Title page
            fig = plt.figure(figsize=(8.5, 11))
            fig.text(0.5, 0.8, 'Soteria IDS Security Report', 
                    ha='center', va='center', fontsize=24, weight='bold')
            fig.text(0.5, 0.7, f'Report Period: Last {hours} hours',
                    ha='center', va='center', fontsize=16)
            fig.text(0.5, 0.6, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
                    ha='center', va='center', fontsize=14)
            
            # Summary statistics
            if threat_stats := stats.get('threat_stats'):
                summary_text = f"""
Total Threats: {threat_stats.get('total_threats', 0)}
Critical: {threat_stats.get('critical', 0)}
High: {threat_stats.get('high', 0)}
Medium: {threat_stats.get('medium', 0)}
Low: {threat_stats.get('low', 0)}
"""
                fig.text(0.5, 0.4, summary_text, ha='center', va='center', 
                        fontsize=12, family='monospace')
            
            pdf.savefig(fig, bbox_inches='tight')
            plt.close()
            
            # Threat distribution pie chart
            if threat_stats := stats.get('threat_stats'):
                fig, ax = plt.subplots(figsize=(8, 6))
                severities = ['Critical', 'High', 'Medium', 'Low']
                counts = [
                    threat_stats.get('critical', 0),
                    threat_stats.get('high', 0),
                    threat_stats.get('medium', 0),
                    threat_stats.get('low', 0)
                ]
                colors = ['#ff0000', '#ff9900', '#ffcc00', '#00ff00']
                
                # Filter out zero values
                non_zero = [(s, c, col) for s, c, col in zip(severities, counts, colors) if c > 0]
                if non_zero:
                    severities, counts, colors = zip(*non_zero)
                    ax.pie(counts, labels=severities, colors=colors, autopct='%1.1f%%')
                    ax.set_title('Threat Distribution by Severity')
                else:
                    ax.text(0.5, 0.5, 'No threats detected', ha='center', va='center')
                
                pdf.savefig(fig, bbox_inches='tight')
                plt.close()
            
            # Threat timeline
            if threats:
                fig, ax = plt.subplots(figsize=(10, 6))
                df = pd.DataFrame(threats)
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                df['hour'] = df['timestamp'].dt.floor('H')
                
                threat_counts = df.groupby(['hour', 'severity']).size().unstack(fill_value=0)
                
                colors = {
                    'critical': '#ff0000',
                    'high': '#ff9900',
                    'medium': '#ffcc00',
                    'low': '#00ff00'
                }
                
                for severity in ['critical', 'high', 'medium', 'low']:
                    if severity in threat_counts.columns:
                        ax.plot(threat_counts.index, threat_counts[severity], 
                               label=severity.capitalize(), color=colors[severity],
                               marker='o', markersize=4)
                
                ax.set_xlabel('Time')
                ax.set_ylabel('Number of Threats')
                ax.set_title('Threat Activity Timeline')
                ax.legend()
                ax.xaxis.set_major_formatter(mdates.DateFormatter('%m/%d %H:%M'))
                plt.xticks(rotation=45)
                
                pdf.savefig(fig, bbox_inches='tight')
                plt.close()
            
            # Top threat sources
            if threats:
                fig, ax = plt.subplots(figsize=(10, 6))
                df = pd.DataFrame(threats)
                
                if 'source_ip' in df.columns:
                    top_sources = df['source_ip'].value_counts().head(10)
                    
                    ax.barh(range(len(top_sources)), top_sources.values, color='#4fbdba')
                    ax.set_yticks(range(len(top_sources)))
                    ax.set_yticklabels(top_sources.index)
                    ax.set_xlabel('Number of Threats')
                    ax.set_title('Top 10 Threat Sources')
                    
                    for i, v in enumerate(top_sources.values):
                        ax.text(v + 0.1, i, str(v), va='center')
                
                pdf.savefig(fig, bbox_inches='tight')
                plt.close()
            
            # Threat types distribution
            if threat_types := stats.get('threat_types'):
                fig, ax = plt.subplots(figsize=(10, 6))
                
                types = list(threat_types.keys())
                counts = list(threat_types.values())
                
                bars = ax.bar(range(len(types)), counts, color='#7ec8e3')
                ax.set_xticks(range(len(types)))
                ax.set_xticklabels([t.replace('_', ' ').title() for t in types], rotation=45)
                ax.set_ylabel('Count')
                ax.set_title('Threats by Type')
                
                for bar, count in zip(bars, counts):
                    height = bar.get_height()
                    ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                           str(count), ha='center', va='bottom')
                
                pdf.savefig(fig, bbox_inches='tight')
                plt.close()
    
    def generate_dashboard_charts(self) -> Dict[str, str]:
        """Generate charts for web dashboard (returns base64 encoded images)"""
        charts = {}
        
        try:
            # Get data
            threats = self.db_logger.get_threat_events(
                start_time=datetime.now() - timedelta(hours=24),
                limit=1000
            )
            stats = self.db_logger.get_statistics(hours=24)
            
            # Generate threat severity chart
            if threat_stats := stats.get('threat_stats'):
                fig, ax = plt.subplots(figsize=(6, 4))
                severities = ['Critical', 'High', 'Medium', 'Low']
                counts = [
                    threat_stats.get('critical', 0),
                    threat_stats.get('high', 0),
                    threat_stats.get('medium', 0),
                    threat_stats.get('low', 0)
                ]
                colors = ['#ff0000', '#ff9900', '#ffcc00', '#00ff00']
                
                ax.bar(severities, counts, color=colors)
                ax.set_title('Threats by Severity (24h)')
                ax.set_ylabel('Count')
                
                buf = BytesIO()
                plt.savefig(buf, format='png', bbox_inches='tight', 
                           facecolor='#1a1a2e', edgecolor='none')
                buf.seek(0)
                charts['severity'] = base64.b64encode(buf.read()).decode()
                plt.close()
            
            # Generate timeline chart
            if threats:
                fig, ax = plt.subplots(figsize=(8, 4))
                df = pd.DataFrame(threats)
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                df['hour'] = df['timestamp'].dt.floor('H')
                
                hourly_counts = df.groupby('hour').size()
                
                ax.plot(hourly_counts.index, hourly_counts.values, 
                       color='#4fbdba', marker='o', markersize=4)
                ax.set_xlabel('Time')
                ax.set_ylabel('Threats')
                ax.set_title('Threat Activity (24h)')
                ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
                plt.xticks(rotation=45)
                
                buf = BytesIO()
                plt.savefig(buf, format='png', bbox_inches='tight',
                           facecolor='#1a1a2e', edgecolor='none')
                buf.seek(0)
                charts['timeline'] = base64.b64encode(buf.read()).decode()
                plt.close()
            
        except Exception as e:
            logger.error(f"Error generating dashboard charts: {e}")
        
        return charts