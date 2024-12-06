import plotly.graph_objs as go
import plotly.io as pio

class SecurityVisualizer:
    def __init__(self, log_analyzer):
        """
        Initialize visualizer with log analyzer data
        """
        self.log_analyzer = log_analyzer
    
    def ip_request_distribution(self):
        """
        Create a bar chart of IP request distribution
        """
        ip_requests = dict(self.log_analyzer.ip_requests)    
        fig = go.Figure(data=[go.Bar(
            x=list(ip_requests.keys()),
            y=list(ip_requests.values()),
            marker_color='rgba(58, 71, 80, 0.6)',
            name='IP Requests'
        )])   
        fig.update_layout(
            title='IP Request Distribution',
            xaxis_title='IP Address',
            yaxis_title='Number of Requests',
            template='plotly_white'
        )   
        pio.write_html(fig, file='ip_requests_visualization.html')  
        return fig.to_html(full_html=False)
    
    def endpoint_access_heatmap(self):
        """
        Create a heatmap of endpoint access
        """
        endpoints = list(self.log_analyzer.endpoint_counts.keys())
        ips = list(set(entry['ip'] for entry in self.log_analyzer.log_entries))   
        access_matrix = []
        for ip in ips:
            ip_entries = [entry for entry in self.log_analyzer.log_entries if entry['ip'] == ip]
            row = [sum(1 for entry in ip_entries if entry['endpoint'] == endpoint) for endpoint in endpoints]
            access_matrix.append(row)      
        fig = go.Figure(data=go.Heatmap(
            z=access_matrix,
            x=endpoints,
            y=ips,
            colorscale='Viridis'
        ))    
        fig.update_layout(
            title='Endpoint Access Heatmap',
            xaxis_title='Endpoints',
            yaxis_title='IP Addresses',
            template='plotly_white'
        ) 
        pio.write_html(fig, file='endpoint_access_heatmap.html')   
        return fig.to_html(full_html=False)
