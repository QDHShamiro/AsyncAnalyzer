$script:mlModelVersion = 2
$script:mlIntercept = -3.595535
$script:mlFeatureOrder = @('pkgpath','cheatsite','strong_sig','weak_sig','fullwidth_str','fullwidth_cls','japanese_cls','singlechar_cls','numeric_cls','novowel_cls','avg_entropy','high_entropy','reflection','runtime_exec','http_download','http_exfil','nested_hollow','fake_identity','filename_client','random_name','verified','legit_modid')
$script:mlWeights = @{
    'pkgpath' = 1.411735
    'cheatsite' = 1.414517
    'strong_sig' = 3.507748
    'weak_sig' = 2.269847
    'fullwidth_str' = 1.131481
    'fullwidth_cls' = 0.546677
    'japanese_cls' = 0.202722
    'singlechar_cls' = 1.922687
    'numeric_cls' = 0.605933
    'novowel_cls' = -0.66706
    'avg_entropy' = 0.781555
    'high_entropy' = 2.899511
    'reflection' = -1.485873
    'runtime_exec' = 1.274711
    'http_download' = 1.479519
    'http_exfil' = -0.239139
    'nested_hollow' = 2.615867
    'fake_identity' = 1.961105
    'filename_client' = 2.371303
    'random_name' = 0.0
    'verified' = -2.507493
    'legit_modid' = -2.338688
}
$script:mlBaseIntercept = $script:mlIntercept
$script:mlBaseWeights = @{}
foreach ($mlk in $script:mlWeights.Keys) { $script:mlBaseWeights[$mlk] = $script:mlWeights[$mlk] }
$script:mlSamples = 0
$script:RepoRaw = "https://raw.githubusercontent.com/QDHShamiro/AsyncAnalyzer/main/ml"

# Magic bytes for resource types a dropper likes to disguise its payload as. A file that claims one
# of these extensions but does not start with the right header is almost certainly a hidden blob.
$script:magicExt = @{
    'png'  = @(0x89, 0x50, 0x4E, 0x47)
    'gif'  = @(0x47, 0x49, 0x46, 0x38)
    'jpg'  = @(0xFF, 0xD8, 0xFF)
    'jpeg' = @(0xFF, 0xD8, 0xFF)
    'ogg'  = @(0x4F, 0x67, 0x67, 0x53)
    'wav'  = @(0x52, 0x49, 0x46, 0x46)
}
# Text resources should read as text (entropy well under 6). Ciphertext hidden in one spikes to ~8.
$script:textExt = @('json', 'txt', 'properties', 'cfg', 'toml', 'lang', 'mcmeta', 'md', 'yml', 'yaml', 'csv')
