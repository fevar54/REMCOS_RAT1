rule Remcos_RAT_MD5 {
    meta:
        description = "Detects potential presence of Remcos RAT based on MD5 hash"
        author = "Fevar54"
        reference = "threatfox"
    strings:
        $hash1 = "21eee575b2425a16123e5eccb8d280c6"
        $hash2 = "4866f5b9ded12cd58c7153ba0d54cc3c"
        $hash3 = "9fe11f84460abd22cc955530ca89cf8c"
        $hash4 = "bcae06ceab767b7cfe609336242afe02"
        $hash5 = "c80e97165d0a93b86bf5e7e193b16cc1"
        $hash6 = "d9e77c8ca14edd3fabf09c01f61c566a"
        $hash7 = "ddc2a9da83a777cb565b4b500d5c7609"
        $hash8 = "e91208f7cebcaa719faf36604d0f7095"
        $hash9 = "ece373b3964de43caf73e842e38703ae"
        $hash10 = "148264565031a8ebb6887a1395a2247a"
        $hash11 = "28aea11ead737cf22363fd0131c59b47"
        $hash12 = "4733810f2e9c33071bbb7faf9ca3fe52"
        $hash13 = "99e19c4a4a8a972005902bf6129867e9"
        $hash14 = "ced0aaa0c6730eb5e144a6bc12821e6f"
    condition:
        any of ($hash*) or any of them
}
