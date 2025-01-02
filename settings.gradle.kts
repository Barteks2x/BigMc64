plugins {
    id("org.gradle.toolchains.foojay-resolver-convention").version("0.8.0")
}
rootProject.name = "BigMc64"

if (file("asm").exists()) {
    includeBuild("asm") {
        name = "asm"
        dependencySubstitution {
            substitute(module("org.ow2.asm:asm")).using(project(":asm"))
            substitute(module("org.ow2.asm:asm-tree")).using(project(":asm-tree"))
            substitute(module("org.ow2.asm:asm-analysis")).using(project(":asm-analysis"))
        }
    }
}