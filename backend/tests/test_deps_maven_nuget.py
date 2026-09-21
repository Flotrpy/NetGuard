import json

from netguard.scanners.dependencies.parsers import maven, nuget


def names(res):
    return {(p.name, p.version) for p in res.packages}


POM = """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
  <properties><log4j.version>2.14.1</log4j.version></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>1.30</version></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>${log4j.version}</version></dependency>
    <dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId></dependency>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version><scope>test</scope></dependency>
    <dependency><groupId>org.spring</groupId><artifactId>managed-elsewhere</artifactId></dependency>
    <dependency><groupId>x</groupId><artifactId>ranged</artifactId><version>[1.0,2.0)</version></dependency>
  </dependencies>
</project>
"""


def test_pom_resolves_properties_and_dependency_management():
    res = maven.parse_pom(POM, "pom.xml")
    assert names(res) == {
        ("org.apache.logging.log4j:log4j-core", "2.14.1"),
        ("org.yaml:snakeyaml", "1.30"),
        ("junit:junit", "4.13.2"),
    }
    assert next(p for p in res.packages if p.name == "junit:junit").dev
    assert "2 dependencies have no resolvable fixed version" in res.warnings[0]
    log4j = next(p for p in res.packages if "log4j" in p.name)
    assert "log4j-core" in POM.splitlines()[log4j.line - 1]


def test_pom_xml_bombs_and_xxe_are_rejected_not_expanded():
    bomb = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
            '<!ENTITY lol2 "&lol;&lol;&lol;&lol;">]><project>&lol2;</project>')
    res = maven.parse_pom(bomb, "pom.xml")
    assert res.packages == [] and "could not parse XML" in res.warnings[0]
    xxe = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><project>&e;</project>'
    assert "could not parse XML" in maven.parse_pom(xxe, "pom.xml").warnings[0]
    assert "could not parse XML" in maven.parse_pom("<not xml", "pom.xml").warnings[0]


GRADLE = """
dependencies {
    implementation 'org.apache.commons:commons-text:1.9'
    implementation("com.google.guava:guava:30.0-jre")
    testImplementation group: 'junit', name: 'junit', version: '4.12'
    api "io.netty:netty-all:${nettyVersion}"
    // implementation 'commented:out:1.0'
    implementation 'dyn:amic:1.+'
}
"""


def test_gradle_build_string_and_map_notation():
    res = maven.parse_gradle_build(GRADLE, "build.gradle")
    assert names(res) == {
        ("org.apache.commons:commons-text", "1.9"),
        ("com.google.guava:guava", "30.0-jre"),
        ("junit:junit", "4.12"),
    }
    assert next(p for p in res.packages if p.name == "junit:junit").dev
    assert "variables/dynamic versions" in res.warnings[0]


def test_gradle_lockfile():
    lock = "# comment\norg.slf4j:slf4j-api:1.7.30=compileClasspath,runtimeClasspath\njunit:junit:4.13=testCompileClasspath\nempty=annotationProcessor\n"
    res = maven.parse_gradle_lockfile(lock, "gradle.lockfile")
    assert names(res) == {("org.slf4j:slf4j-api", "1.7.30"), ("junit:junit", "4.13")}
    assert next(p for p in res.packages if p.name == "junit:junit").dev


def test_nuget_packages_config():
    xml = '<packages><package id="Newtonsoft.Json" version="9.0.1" targetFramework="net45" /></packages>'
    assert names(nuget.parse_packages_config(xml, "packages.config")) == {("Newtonsoft.Json", "9.0.1")}


CSPROJ = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><NJ>12.0.1</NJ></PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="$(NJ)" />
    <PackageReference Include="Serilog"><Version>2.9.0</Version></PackageReference>
    <PackageReference Include="Floating" Version="1.*" />
    <PackageReference Include="Ranged" Version="[1.0,2.0)" />
    <PackageReference Include="Exact" Version="[3.1.0]" />
  </ItemGroup>
</Project>"""


def test_csproj_property_nested_version_and_skips():
    res = nuget.parse_project_file(CSPROJ, "app.csproj")
    assert names(res) == {("Newtonsoft.Json", "12.0.1"), ("Serilog", "2.9.0"), ("Exact", "3.1.0")}
    assert "2 package references" in res.warnings[0]


def test_nuget_lock_with_transitive_chain():
    lock = {"version": 1, "dependencies": {"net6.0": {
        "A": {"type": "Direct", "resolved": "1.0.0", "dependencies": {"B": "2.0.0"}},
        "B": {"type": "Transitive", "resolved": "2.0.0", "dependencies": {"C": "3.0.0"}},
        "C": {"type": "Transitive", "resolved": "3.0.0"},
    }}}
    res = nuget.parse_packages_lock(json.dumps(lock), "packages.lock.json")
    c = next(p for p in res.packages if p.name == "C")
    assert c.path == ["A", "B", "C"] and not c.direct
    assert next(p for p in res.packages if p.name == "A").direct


def test_bad_inputs_warn():
    assert "invalid JSON" in nuget.parse_packages_lock("{", "l.json").warnings[0]
    assert "could not parse XML" in nuget.parse_project_file("<x", "a.csproj").warnings[0]
