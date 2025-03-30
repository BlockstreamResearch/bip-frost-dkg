#!/usr/bin/env python3

"""
Driver script for generating test vector JSON files.
Outputs are saved in the "vectors/" directory.
"""

import sys
from pathlib import Path
from vector_generator import util
from vector_generator.others import (
    generate_hostpubkey_vectors,
    generate_params_id_vectors,
    generate_recover_vectors,
)
from vector_generator.participant import (
    generate_participant_step1_vectors,
    generate_participant_step2_vectors,
    generate_participant_finalize_vectors,
    generate_participant_investigate_vectors,
)
from vector_generator.coordinator import (
    generate_coordinator_step1_vectors,
    generate_coordinator_finalize_vectors,
    generate_coordinator_investigate_vectors,
)


def main():
    output_dir = Path("vectors")
    output_dir.mkdir(parents=True, exist_ok=True)

    util.write_json(
        output_dir / "hostpubkey_gen_vectors.json", generate_hostpubkey_vectors()
    )
    util.write_json(output_dir / "params_id_vectors.json", generate_params_id_vectors())
    util.write_json(output_dir / "recover_vectors.json", generate_recover_vectors())
    util.write_json(
        output_dir / "participant_step1_vectors.json",
        generate_participant_step1_vectors(),
    )
    util.write_json(
        output_dir / "participant_step2_vectors.json",
        generate_participant_step2_vectors(),
    )
    util.write_json(
        output_dir / "participant_finalize_vectors.json",
        generate_participant_finalize_vectors(),
    )
    util.write_json(
        output_dir / "participant_investigate_vectors.json",
        generate_participant_investigate_vectors(),
    )
    util.write_json(
        output_dir / "coordinator_step1_vectors.json",
        generate_coordinator_step1_vectors(),
    )
    util.write_json(
        output_dir / "coordinator_finalize_vectors.json",
        generate_coordinator_finalize_vectors(),
    )
    util.write_json(
        output_dir / "coordinator_investigate_vectors.json",
        generate_coordinator_investigate_vectors(),
    )
    print("Test vectors generated successfully")


if __name__ == "__main__":
    sys.exit(main())
