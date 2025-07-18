import React, { useState, useEffect } from 'react';
import {
  AppBar,
  Toolbar,
  Typography,
  Container,
  Grid,
  Card,
  CardContent,
  CardActions,
  Button,
  Box,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Alert,
  CircularProgress,
  ThemeProvider,
  createTheme,
  CssBaseline,
  Paper,
  List,
  ListItem,
  ListItemText,
  ListItemIcon
} from '@mui/material';
import {
  Security,
  BugReport,
  Search,
  Web,
  Lock,
  Warning,
  CheckCircle,
  Error,
  Info
} from '@mui/icons-material';
import './App.css';

const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#00ff41',
    },
    secondary: {
      main: '#ff4444',
    },
    background: {
      default: '#0d0d0d',
      paper: '#1a1a1a',
    },
  },
  typography: {
    fontFamily: '"Courier New", monospace',
  },
});

interface Module {
  id: string;
  name: string;
  description: string;
}

interface ScanResult {
  success: boolean;
  results?: any;
  error?: string;
}

function App() {
  const [modules, setModules] = useState<Module[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedModule, setSelectedModule] = useState<Module | null>(null);
  const [target, setTarget] = useState('');
  const [scanResults, setScanResults] = useState<ScanResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [dialogOpen, setDialogOpen] = useState(false);

  useEffect(() => {
    fetchModules();
  }, []);

  const fetchModules = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/junior-pentest/modules');
      const data = await response.json();
      setModules(data.modules);
    } catch (error) {
      console.error('Failed to fetch modules:', error);
    } finally {
      setLoading(false);
    }
  };

  const runScan = async () => {
    if (!selectedModule || !target) return;

    setScanning(true);
    setScanResults(null);

    try {
      const response = await fetch(
        `http://localhost:8000/api/junior-pentest/scan/${selectedModule.id}?target=${encodeURIComponent(target)}`,
        { method: 'POST' }
      );
      const data = await response.json();
      setScanResults(data);
    } catch (error) {
      setScanResults({ success: false, error: 'Failed to run scan' });
    } finally {
      setScanning(false);
    }
  };

  const handleModuleClick = (module: Module) => {
    setSelectedModule(module);
    setDialogOpen(true);
    setScanResults(null);
  };

  const getModuleIcon = (moduleId: string) => {
    const iconMap: { [key: string]: React.ReactNode } = {
      'application_walker': <Web />,
      'content_discovery': <Search />,
      'subdomain_enum': <Web />,
      'auth_bypass': <Lock />,
      'idor_detection': <Security />,
      'file_inclusion': <BugReport />,
      'ssrf_detection': <Warning />,
      'xss_scanner': <BugReport />,
      'race_conditions': <Warning />,
      'command_injection': <BugReport />,
      'sql_injection': <BugReport />
    };
    return iconMap[moduleId] || <Security />;
  };

  const getModuleCategory = (moduleId: string) => {
    if (['application_walker', 'content_discovery', 'subdomain_enum'].includes(moduleId)) {
      return 'Reconnaissance';
    }
    if (['auth_bypass', 'idor_detection'].includes(moduleId)) {
      return 'Authentication';
    }
    return 'Vulnerability Detection';
  };

  const renderScanResults = () => {
    if (!scanResults) return null;

    if (!scanResults.success) {
      return (
        <Alert severity="error" sx={{ mt: 2 }}>
          <strong>Scan Failed:</strong> {scanResults.error}
        </Alert>
      );
    }

    const results = scanResults.results;
    return (
      <Paper sx={{ mt: 2, p: 2, bgcolor: '#0a0a0a' }}>
        <Typography variant="h6" gutterBottom color="primary">
          Scan Results for {results.target}
        </Typography>
        
        {results.findings && (
          <Box mt={2}>
            {results.findings.technologies && results.findings.technologies.length > 0 && (
              <Box mb={2}>
                <Typography variant="subtitle1" color="secondary">Technologies Detected:</Typography>
                {results.findings.technologies.map((tech: any, index: number) => (
                  <Chip key={index} label={`${tech.name}: ${tech.value}`} size="small" sx={{ mr: 1, mb: 1 }} />
                ))}
              </Box>
            )}

            {results.findings.vulnerabilities && results.findings.vulnerabilities.length > 0 && (
              <Box mb={2}>
                <Typography variant="subtitle1" color="error">Security Issues Found:</Typography>
                <List dense>
                  {results.findings.vulnerabilities.map((vuln: any, index: number) => (
                    <ListItem key={index}>
                      <ListItemIcon>
                        <Error color="error" />
                      </ListItemIcon>
                      <ListItemText
                        primary={vuln.description}
                        secondary={`Severity: ${vuln.severity} - ${vuln.recommendation}`}
                      />
                    </ListItem>
                  ))}
                </List>
              </Box>
            )}

            {results.findings.endpoints && results.findings.endpoints.length > 0 && (
              <Box mb={2}>
                <Typography variant="subtitle1" color="info">Endpoints Found:</Typography>
                <List dense>
                  {results.findings.endpoints.slice(0, 5).map((endpoint: string, index: number) => (
                    <ListItem key={index}>
                      <ListItemIcon>
                        <Info color="info" />
                      </ListItemIcon>
                      <ListItemText primary={endpoint} />
                    </ListItem>
                  ))}
                </List>
              </Box>
            )}

            {results.findings.subdomains_found && results.findings.subdomains_found.length > 0 && (
              <Box mb={2}>
                <Typography variant="subtitle1" color="success">Subdomains Found:</Typography>
                <List dense>
                  {results.findings.subdomains_found.map((subdomain: any, index: number) => (
                    <ListItem key={index}>
                      <ListItemIcon>
                        <CheckCircle color="success" />
                      </ListItemIcon>
                      <ListItemText
                        primary={subdomain.subdomain}
                        secondary={`IPs: ${subdomain.ips.join(', ')}`}
                      />
                    </ListItem>
                  ))}
                </List>
              </Box>
            )}
          </Box>
        )}

        <Box mt={2}>
          <Typography variant="caption" color="textSecondary">
            Scan completed at: {new Date(results.metadata.scan_time * 1000).toLocaleString()}
          </Typography>
        </Box>
      </Paper>
    );
  };

  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      <Box sx={{ flexGrow: 1, minHeight: '100vh', bgcolor: 'background.default' }}>
        <AppBar position="static">
          <Toolbar>
            <Security sx={{ mr: 2 }} />
            <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
              CyberSec Toolkit v1.0.0
            </Typography>
            <Typography variant="body2">
              Junior Pentest Suite
            </Typography>
          </Toolbar>
        </AppBar>

        <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
          <Typography variant="h4" gutterBottom color="primary" align="center">
            🔒 Web Application Security Testing
          </Typography>
          
          <Typography variant="body1" paragraph align="center" color="textSecondary">
            ⚠️ For authorized testing only! Ensure you have proper permission before testing any target.
          </Typography>

          {loading ? (
            <Box display="flex" justifyContent="center" mt={4}>
              <CircularProgress />
            </Box>
          ) : (
            <Box
              sx={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
                gap: 3,
                mt: 2,
              }}
            >
              {modules.map((module) => (
                <Box key={module.id}>
                  <Card 
                    sx={{ 
                      height: '100%', 
                      bgcolor: 'background.paper',
                      border: '1px solid #333',
                      '&:hover': { 
                        bgcolor: '#2a2a2a',
                        cursor: 'pointer',
                        transform: 'translateY(-2px)',
                        transition: 'all 0.3s ease'
                      }
                    }}
                    onClick={() => handleModuleClick(module)}
                  >
                    <CardContent>
                      <Box display="flex" alignItems="center" mb={2}>
                        {getModuleIcon(module.id)}
                        <Typography variant="h6" component="div" sx={{ ml: 1 }}>
                          {module.name}
                        </Typography>
                      </Box>
                      <Typography variant="body2" color="textSecondary" paragraph>
                        {module.description}
                      </Typography>
                      <Chip 
                        label={getModuleCategory(module.id)} 
                        size="small" 
                        color="primary" 
                        variant="outlined"
                      />
                    </CardContent>
                    <CardActions>
                      <Button size="small" color="primary">
                        Run Scan
                      </Button>
                    </CardActions>
                  </Card>
                </Box>
              ))}
            </Box>
          )}
        </Container>

        <Dialog 
          open={dialogOpen} 
          onClose={() => setDialogOpen(false)}
          maxWidth="md"
          fullWidth
          PaperProps={{
            sx: { bgcolor: 'background.paper' }
          }}
        >
          <DialogTitle>
            {selectedModule && (
              <Box display="flex" alignItems="center">
                {getModuleIcon(selectedModule.id)}
                <Typography variant="h6" sx={{ ml: 1 }}>
                  {selectedModule.name}
                </Typography>
              </Box>
            )}
          </DialogTitle>
          <DialogContent>
            {selectedModule && (
              <>
                <Typography variant="body1" paragraph>
                  {selectedModule.description}
                </Typography>
                
                <TextField
                  fullWidth
                  label="Target URL/Domain"
                  placeholder="https://example.com or example.com"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  sx={{ mt: 2 }}
                  disabled={scanning}
                />

                {scanning && (
                  <Box display="flex" alignItems="center" justifyContent="center" mt={3}>
                    <CircularProgress size={24} sx={{ mr: 2 }} />
                    <Typography>Running scan...</Typography>
                  </Box>
                )}

                {renderScanResults()}
              </>
            )}
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setDialogOpen(false)}>
              Close
            </Button>
            <Button 
              onClick={runScan} 
              variant="contained" 
              disabled={!target || scanning}
              color="primary"
            >
              {scanning ? 'Scanning...' : 'Run Scan'}
            </Button>
          </DialogActions>
        </Dialog>
      </Box>
    </ThemeProvider>
  );
}

export default App;
